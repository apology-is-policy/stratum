//! SWISS-4m: passphrase prompt + keyfile-magic detection helpers.
//!
//! Two responsibilities:
//!   1. `is_keyfile_encrypted(path)` peeks the first 4 bytes of a
//!      keyfile and returns true iff the magic is KFP1 (passphrase-
//!      encrypted format). Used by the TUI to decide whether to
//!      prompt before spawning stratumd.
//!   2. `prompt_passphrase(label)` reads a line from the controlling
//!      terminal, /dev/tty, with echo and canonical mode off. Returned
//!      as `Vec<u8>` (NOT NUL-
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

/// Wipes a secret typed into a String, including what was backspaced over.
pub fn wipe_string(s: &mut String) {
    let v = unsafe { s.as_mut_vec() };
    let cap = v.capacity();
    v.resize(cap, 0);
    for b in v.iter_mut() {
        unsafe { std::ptr::write_volatile(b as *mut u8, 0); }
    }
    v.clear();
}

/// Appends to a secret, wiping the old buffer rather than leaving it to the
/// allocator when the secret outgrows it.
pub fn push_secret(s: &mut String, c: char) {
    if s.capacity() - s.len() < c.len_utf8() {
        let mut grown = String::with_capacity((s.len() + c.len_utf8()).max(64) * 2);
        grown.push_str(s);
        wipe_string(s);
        *s = grown;
    }
    s.push(c);
}

/// What a dialog's field holds, which may be a passphrase: wiped when it goes, each
/// copy included, and when it outgrows its buffer. What the terminal library buffered
/// on the way in is out of reach.
#[derive(Clone, Default)]
pub struct SecretText(String);
impl SecretText {
    pub fn push(&mut self, c: char) { push_secret(&mut self.0, c); }
    pub fn pop(&mut self) -> Option<char> { self.0.pop() }
}
impl From<String> for SecretText {
    fn from(s: String) -> Self { Self(s) }
}
impl std::ops::Deref for SecretText {
    type Target = str;
    fn deref(&self) -> &str { &self.0 }
}
impl Drop for SecretText {
    fn drop(&mut self) { wipe_string(&mut self.0); }
}
impl std::fmt::Debug for SecretText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretText(..)")
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
        // The whole buffer, since a backspace leaves its byte past the length. Volatile
        // so the optimizer can't elide the wipe.
        let (p, cap) = (self.0.as_mut_ptr(), self.0.capacity());
        for i in 0..cap {
            unsafe { std::ptr::write_volatile(p.add(i), 0); }
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
    prompt_on(&tty, label)
}

/// With canonical mode off the line discipline edits nothing, so the keys a cooked
/// terminal would act on are acted on here: DEL and BS erase a byte, Ctrl-U the line,
/// Ctrl-D gives up. Only Enter submits.
fn prompt_on(tty: &File, label: &str) -> Result<Zeroizing> {
    let fd = tty.as_raw_fd();

    // Print label to /dev/tty (NOT stdout — stdout might be piped).
    {
        let mut writer = tty;
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
    // Never grows, as the refusal comes at 1024, and every way out of here wipes it.
    let mut buf = Zeroizing::new(Vec::with_capacity(1025));
    let mut byte = [0u8; 1];
    let mut reader = tty;
    let given_up = loop {
        match reader.read(&mut byte) {
            // Only a hangup ends a read here: what was typed was never submitted.
            Ok(0) => break Some("the terminal closed at the passphrase prompt"),
            Ok(_) => match byte[0] {
                b'\n' => break None,
                0x7f | 0x08 => {
                    buf.0.pop();
                }
                0x15 => buf.0.clear(),
                0x04 => break Some("the passphrase prompt was given up (Ctrl-D)"),
                b => {
                    if buf.len() >= 1024 {
                        break Some("passphrase exceeds 1024 bytes");
                    }
                    buf.0.push(b);
                }
            },
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                unsafe { std::ptr::write_volatile(&mut byte[0], 0) };
                let _ = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &orig) };
                return Err(anyhow!("read tty: {e}"));
            }
        }
    };
    unsafe { std::ptr::write_volatile(&mut byte[0], 0) };

    // Restore termios.
    let _ = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &orig) };
    // Print a trailing newline so the next line of the prompt isn't
    // glued to the user's hidden input.
    {
        let mut writer = tty;
        let _ = writer.write_all(b"\n");
    }

    if let Some(why) = given_up {
        bail!("{why}");
    }
    if buf.is_empty() {
        bail!("empty passphrase refused");
    }
    Ok(buf)
}

#[cfg(test)]
mod prompt_tests {
    use super::*;
    use std::os::unix::io::FromRawFd;
    use std::time::{Duration, Instant};

    /// The prompt on a pty's slave, typed to through its master once canonical mode
    /// is off (before that the line discipline would act on the keys itself), the
    /// master then closed or kept open.
    fn typed(keys: &[u8], then_close: bool) -> Result<Vec<u8>> {
        let (mut m, mut s) = (0, 0);
        let rc = unsafe {
            libc::openpty(&mut m, &mut s, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
        };
        assert_eq!(rc, 0, "openpty: {}", io::Error::last_os_error());
        let probe = unsafe { libc::dup(s) };
        let (mut master, slave) = unsafe { (File::from_raw_fd(m), File::from_raw_fd(s)) };
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(prompt_on(&slave, "P: ").map(|z| z.as_bytes().to_vec()));
        });
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let mut t: libc::termios = unsafe { std::mem::zeroed() };
            if unsafe { libc::tcgetattr(probe, &mut t) } == 0 && t.c_lflag & libc::ICANON == 0 {
                break;
            }
            assert!(Instant::now() < end, "the prompt never turned canonical mode off");
            std::thread::sleep(Duration::from_millis(5));
        }
        unsafe { libc::close(probe) };
        master.write_all(keys).expect("type");
        if then_close {
            drop(master);
            return rx.recv_timeout(Duration::from_secs(5)).expect("the prompt never returned");
        }
        let got = rx.recv_timeout(Duration::from_secs(5)).expect("the prompt never returned");
        drop(master);
        got
    }

    #[test]
    fn the_terminal_closing_before_enter_submits_nothing() {
        let got = typed(b"correct horse", true);
        assert!(got.is_err(), "a hangup before Enter gave {:?}", got.map(|v| String::from_utf8_lossy(&v).into_owned()));
    }

    #[test]
    fn ctrl_u_clears_what_was_typed() {
        assert_eq!(typed(b"wrong\x15right\n", false).expect("a passphrase"), b"right");
    }

    #[test]
    fn ctrl_d_gives_up_and_submits_nothing() {
        let got = typed(b"half\x04", false);
        assert!(matches!(&got, Err(e) if e.to_string().contains("given up")), "Ctrl-D gave {:?}", got.map(|v| v.len()));
    }

    #[test]
    fn delete_erases_one_byte() {
        assert_eq!(typed(b"rigxht\x7f\x7f\x7fht\n", false).expect("a passphrase"), b"right");
    }
}

#[cfg(test)]
mod secret_tests {
    use super::*;

    #[test]
    fn a_secret_keeps_every_character_as_it_grows() {
        let mut s = String::new();
        let want: String = "pass\u{e9}phrase".repeat(20);
        for c in want.chars() {
            push_secret(&mut s, c);
        }
        assert_eq!(s, want);
    }

    #[test]
    fn a_wipe_leaves_the_whole_buffer_zero() {
        let mut s = String::from("secret");
        s.pop();
        let cap = s.capacity();
        wipe_string(&mut s);
        assert!(s.is_empty());
        // Within the capacity, and the wipe wrote every byte of it.
        let raw = unsafe { std::slice::from_raw_parts(s.as_ptr(), cap) };
        assert!(raw.iter().all(|&b| b == 0));
    }
}
