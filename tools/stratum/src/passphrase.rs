//! SWISS-4m: passphrase prompt + keyfile-magic detection helpers.
//!
//! Two responsibilities:
//!   1. `is_keyfile_encrypted(path)` peeks the first 4 bytes of a
//!      keyfile and returns true iff the magic is KFP1 (passphrase-
//!      encrypted format). Used by the TUI to decide whether to
//!      prompt before spawning stratumd.
//!   2. `prompt_passphrase(label)` reads a line from the controlling
//!      terminal with echo OFF (raw `read(STDIN, 1)` after termios
//!      ICANON+ECHO masked). Returned as `Vec<u8>` (NOT NUL-
//!      terminated). Caller is responsible for `drop` (which clears
//!      via the `Zeroizing` wrapper) when no longer needed.

use anyhow::{anyhow, bail, Context, Result};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;

const KFIL_MAGIC: u32 = 0x4C49464B;     // 'KFIL' — plaintext v1
const KFP1_MAGIC: u32 = 0x31504650;     // 'KFP1' — passphrase-encrypted

/// Peek the first 4 bytes; return Ok(true) iff the magic indicates
/// a passphrase-encrypted keyfile. Returns Ok(false) for plaintext
/// or unrecognized magic. Returns Err on I/O failure / short file.
pub fn is_keyfile_encrypted(path: &Path) -> Result<bool> {
    let mut f = File::open(path)
        .with_context(|| format!("open keyfile {}", path.display()))?;
    let mut hdr = [0u8; 4];
    f.read_exact(&mut hdr)
        .with_context(|| format!("read keyfile magic {}", path.display()))?;
    let magic = u32::from_le_bytes(hdr);
    match magic {
        KFP1_MAGIC => Ok(true),
        KFIL_MAGIC => Ok(false),
        _ => bail!(
            "{}: unrecognized keyfile magic 0x{:08x}",
            path.display(), magic
        ),
    }
}

/// `Zeroizing<Vec<u8>>` — a Vec wrapper that wipes its backing buffer
/// on drop. Equivalent to the `zeroize` crate's `Zeroizing` but rolled
/// here to avoid adding a dep.
pub struct Zeroizing(Vec<u8>);
impl Zeroizing {
    pub fn new(v: Vec<u8>) -> Self { Self(v) }
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
    pub fn len(&self) -> usize { self.0.len() }
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}
impl Drop for Zeroizing {
    fn drop(&mut self) {
        // Volatile write so the optimizer can't elide the wipe.
        for b in self.0.iter_mut() {
            unsafe { std::ptr::write_volatile(b as *mut u8, 0); }
        }
    }
}

/// Prompt the user with `label` (typically "Passphrase: ") on the
/// controlling terminal, read a line with echo off, return as
/// `Zeroizing<Vec<u8>>`. The trailing '\n' is stripped.
///
/// Reads from /dev/tty directly so this works even when stdin/stdout
/// have been redirected (e.g., when the TUI parent's stdout is a
/// pipe). On error (no controlling tty) returns Err.
pub fn prompt_passphrase(label: &str) -> Result<Zeroizing> {
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("open /dev/tty (no controlling terminal?)")?;
    let fd = tty.as_raw_fd();

    // Print label to /dev/tty (NOT stdout — stdout might be piped).
    {
        let mut writer = &tty;
        writer.write_all(label.as_bytes()).context("write prompt")?;
        writer.flush().ok();
    }

    // Save current termios + disable ECHO + ICANON.
    let mut orig: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut orig) } != 0 {
        return Err(anyhow!("tcgetattr failed: {}", io::Error::last_os_error()));
    }
    let mut quiet = orig;
    quiet.c_lflag &= !(libc::ECHO | libc::ICANON);
    quiet.c_cc[libc::VMIN]  = 1;
    quiet.c_cc[libc::VTIME] = 0;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) } != 0 {
        return Err(anyhow!(
            "tcsetattr disable-echo failed: {}", io::Error::last_os_error()));
    }

    // Read a line.
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    let mut reader = &tty;
    loop {
        match reader.read(&mut byte) {
            Ok(0) => break,         // EOF
            Ok(_) => {
                if byte[0] == b'\n' { break; }
                if byte[0] == 0x7f || byte[0] == 0x08 {
                    // Backspace / DEL — pop one byte if any.
                    buf.pop();
                    continue;
                }
                if buf.len() >= 1024 {
                    // Refuse runaway input.
                    let _ = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &orig) };
                    bail!("passphrase exceeds 1024 bytes");
                }
                buf.push(byte[0]);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                let _ = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &orig) };
                return Err(anyhow!("read tty: {e}"));
            }
        }
    }

    // Restore termios.
    let _ = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &orig) };
    // Print a trailing newline so the next line of the prompt isn't
    // glued to the user's hidden input.
    {
        let mut writer = &tty;
        let _ = writer.write_all(b"\n");
    }

    if buf.is_empty() {
        bail!("empty passphrase refused");
    }
    Ok(Zeroizing::new(buf))
}
