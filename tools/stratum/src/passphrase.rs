//! SWISS-4m: passphrase prompt + keyfile-magic detection helpers.
//!
//! Two responsibilities:
//!   1. `is_keyfile_encrypted(path)` peeks the first 4 bytes of a
//!      keyfile and returns true iff the magic is KFP1 (passphrase-
//!      encrypted format). Used by the TUI to decide whether to
//!      prompt before spawning stratumd.
//!   2. `prompt_passphrase(label)` reads a line from the controlling
//!      terminal, /dev/tty, with echo and canonical mode off. The bytes
//!      (NOT NUL-terminated) come back in a `Zeroizing`, wiped when it
//!      goes, with an `EchoHeld`: echo stays off until the caller lets
//!      that go.

use anyhow::{anyhow, bail, Context, Result};
use std::cell::UnsafeCell;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};

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
/// on the way in is out of reach. Typed as a passphrase it keeps what read_line keeps,
/// so the same keys make the same passphrase: at most PASSPHRASE_MAX bytes, a character
/// whole or not at all, and past that a count, which no paste can grow into memory.
#[derive(Clone, Default)]
pub struct SecretText {
    text: String,
    over: usize,
}
impl SecretText {
    pub fn type_secret(&mut self, c: char) {
        self.type_within(c, PASSPHRASE_MAX);
    }
    /// The same rule for a field of at most `max` bytes.
    pub fn type_within(&mut self, c: char, max: usize) {
        if self.over > 0 || self.text.len() + c.len_utf8() > max {
            self.over += 1;
        } else {
            push_secret(&mut self.text, c);
        }
    }
    /// Erases the last character typed: one counted past the limit first.
    pub fn erase(&mut self) {
        if self.over > 0 {
            self.over -= 1;
        } else {
            self.text.pop();
        }
    }
    pub fn clear(&mut self) {
        wipe_string(&mut self.text);
        self.over = 0;
    }
    /// Typed past the limit, which a submit refuses.
    pub fn past_limit(&self) -> bool { self.over > 0 }
    /// Characters typed, kept or counted.
    pub fn typed(&self) -> usize { self.text.chars().count() + self.over }
}
impl From<String> for SecretText {
    fn from(text: String) -> Self { Self { text, over: 0 } }
}
impl From<&str> for SecretText {
    fn from(text: &str) -> Self { Self { text: text.to_string(), over: 0 } }
}
impl std::ops::Deref for SecretText {
    type Target = str;
    fn deref(&self) -> &str { &self.text }
}
impl Drop for SecretText {
    fn drop(&mut self) { wipe_string(&mut self.text); }
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
pub fn prompt_passphrase(label: &str) -> Result<(Zeroizing, EchoHeld)> {
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("open /dev/tty (no controlling terminal?)")?;
    prompt_on(tty, label)
}

/// Echo held off after a passphrase was read, until this goes: a key typed while the key
/// is derived, the passphrase again say, is not shown. A job-control stop meanwhile, a
/// SIGTSTP, SIGTTIN or SIGTTOU, gives the terminal back first if the job is in front, as
/// vi and readpassphrase do, so the shell gets it as it was whatever it keeps; each
/// continue in front holds echo off again. A SIGSTOP cannot be caught. Dropping it is the
/// release: the terminal is given back, what was typed meanwhile dropped, only if the job
/// is in front, and it never stops for it. `give_back` is for a caller that uses the
/// terminal next. Like the prompt, it is sound only while its holder is the one thread.
pub struct EchoHeld {
    tty: File,
    orig: libc::termios,
    caught: Vec<(libc::c_int, libc::sigaction)>,
    given: bool,
}

impl EchoHeld {
    /// Gives the terminal back as it was, so that what reads the mode next finds this one and
    /// not the shell's: behind, it waits stopped until `fg`, as any set from behind does. A
    /// stop asked meanwhile, as `stop_asked` tells, ends the wait and leaves the terminal to
    /// the shell, as a drop does. Returns whether the terminal was given back.
    pub fn give_back(mut self, stop_asked: impl Fn() -> bool) -> bool {
        let fd = self.tty.as_raw_fd();
        // A stop or a continue from here on lands once this is done, with the default actions.
        let mut quiet: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut quiet);
            libc::sigaddset(&mut quiet, libc::SIGTSTP);
            libc::sigaddset(&mut quiet, libc::SIGCONT);
        }
        let prev = block(&quiet);
        self.let_go();
        let ttou = take_over(libc::SIGTTOU, &action(stop_and_interrupt, 0));
        let mut given = false;
        loop {
            if !in_front(fd) && stop_asked() {
                break;
            }
            if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &self.orig) } == 0 {
                given = true;
                break;
            }
            // EINTR after each stop behind, so a stop asked meanwhile is seen; EIO, a
            // terminal gone or a group orphaned, ends it.
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                break;
            }
        }
        if let Some(old) = ttou {
            unsafe { libc::sigaction(libc::SIGTTOU, &old, std::ptr::null_mut()) };
        }
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &prev, std::ptr::null_mut()) };
        self.given = true;
        given
    }

    fn let_go(&mut self) {
        if self.caught.is_empty() {
            return;
        }
        for (sig, old) in self.caught.drain(..) {
            unsafe { libc::sigaction(sig, &old, std::ptr::null_mut()) };
        }
        HOLD.fd.store(FREE, Ordering::Release);
    }
}

impl Drop for EchoHeld {
    fn drop(&mut self) {
        if self.given {
            return;
        }
        let fd = self.tty.as_raw_fd();
        // No stop or continue comes between the check and the restore, nor before the
        // handlers go.
        let prev = block(&release_set());
        if unsafe { libc::tcgetpgrp(fd) == libc::getpgrp() } {
            while unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &self.orig) } != 0
                && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
            {}
        }
        self.let_go();
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &prev, std::ptr::null_mut()) };
    }
}

/// What the handlers give back and hold again. One hold at a time owns it.
struct Hold {
    fd: AtomicI32,
    orig: UnsafeCell<MaybeUninit<libc::termios>>,
    held: UnsafeCell<MaybeUninit<libc::termios>>,
}
// The copies are written only by the hold that claimed it (FREE -> CLAIMING), before it
// publishes the terminal in `fd` and installs the handlers, which read them only after
// loading `fd`; it is FREE again only once the handlers are gone.
unsafe impl Sync for Hold {}
const FREE: i32 = -1;
const CLAIMING: i32 = -2;
static HOLD: Hold = Hold {
    fd: AtomicI32::new(FREE),
    orig: UnsafeCell::new(MaybeUninit::uninit()),
    held: UnsafeCell::new(MaybeUninit::uninit()),
};

fn job_control_set() -> libc::sigset_t {
    let mut jobs: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut jobs);
        for sig in [libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU] {
            libc::sigaddset(&mut jobs, sig);
        }
    }
    jobs
}

/// The stops and the continue: what the handlers take while echo is held.
fn release_set() -> libc::sigset_t {
    let mut set = job_control_set();
    unsafe { libc::sigaddset(&mut set, libc::SIGCONT) };
    set
}

fn block(set: &libc::sigset_t) -> libc::sigset_t {
    let mut prev: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, set, &mut prev) };
    prev
}

fn in_front(fd: RawFd) -> bool {
    unsafe { libc::tcgetpgrp(fd) == libc::getpgrp() }
}

fn action(handler: extern "C" fn(libc::c_int), flags: libc::c_int) -> libc::sigaction {
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = handler as libc::sighandler_t;
    act.sa_flags = flags;
    // One at a time: a continue's handler runs once a stop's has returned.
    act.sa_mask = release_set();
    act
}

/// Installs `act` for `sig` unless something else has it, a handler or an ignore, and
/// returns the action to put back.
pub(crate) fn take_over(sig: libc::c_int, act: &libc::sigaction) -> Option<libc::sigaction> {
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(sig, std::ptr::null(), &mut old) } != 0 || old.sa_sigaction != libc::SIG_DFL {
        return None;
    }
    unsafe { libc::sigaction(sig, act, std::ptr::null_mut()) };
    Some(old)
}

/// Catches the stops and the continue while echo is held, each unless something else has
/// it, and returns the actions to put back: none if another hold owns the handlers.
fn catch_stops(fd: RawFd, orig: &libc::termios, held: &libc::termios) -> Vec<(libc::c_int, libc::sigaction)> {
    let mut caught = Vec::new();
    if HOLD.fd.compare_exchange(FREE, CLAIMING, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return caught;
    }
    unsafe {
        (*HOLD.orig.get()).write(*orig);
        (*HOLD.held.get()).write(*held);
    }
    HOLD.fd.store(fd, Ordering::Release);
    for sig in [libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU] {
        if let Some(old) = take_over(sig, &action(stop_given_back, libc::SA_RESTART)) {
            caught.push((sig, old));
        }
    }
    if let Some(old) = take_over(libc::SIGCONT, &action(held_again, libc::SA_RESTART)) {
        caught.push((libc::SIGCONT, old));
    }
    if caught.is_empty() {
        HOLD.fd.store(FREE, Ordering::Release);
    }
    caught
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
fn errno_location() -> *mut libc::c_int {
    unsafe { libc::__error() }
}
#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
fn errno_location() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

/// Stops by `sig`'s default action, set for the moment, and returns once continued.
pub(crate) unsafe fn stop_by(sig: libc::c_int) {
    let mut dfl: libc::sigaction = std::mem::zeroed();
    dfl.sa_sigaction = libc::SIG_DFL;
    libc::sigaction(sig, &dfl, std::ptr::null_mut());
    let mut one: libc::sigset_t = std::mem::zeroed();
    libc::sigemptyset(&mut one);
    libc::sigaddset(&mut one, sig);
    libc::pthread_sigmask(libc::SIG_UNBLOCK, &one, std::ptr::null_mut());
    libc::kill(libc::getpid(), sig);
}

/// In front, the terminal given back; then the stop `sig` asked for; then, continued in
/// front, echo held off again. Behind, the shell has the terminal, and it is not set
/// under it.
extern "C" fn stop_given_back(sig: libc::c_int) {
    let fd = HOLD.fd.load(Ordering::Acquire);
    if fd < 0 {
        return;
    }
    unsafe {
        let errno = *errno_location();
        if in_front(fd) {
            libc::tcsetattr(fd, libc::TCSAFLUSH, (*HOLD.orig.get()).as_ptr());
        }
        stop_by(sig);
        libc::sigaction(sig, &action(stop_given_back, libc::SA_RESTART), std::ptr::null_mut());
        hold_again(fd);
        *errno_location() = errno;
    }
}

/// A continue, after `bg` then `fg` say: in front, echo held off again.
extern "C" fn held_again(_: libc::c_int) {
    let fd = HOLD.fd.load(Ordering::Acquire);
    if fd < 0 {
        return;
    }
    unsafe {
        let errno = *errno_location();
        hold_again(fd);
        *errno_location() = errno;
    }
}

unsafe fn hold_again(fd: RawFd) {
    if in_front(fd) {
        libc::tcsetattr(fd, libc::TCSAFLUSH, (*HOLD.held.get()).as_ptr());
    }
}

/// While give_back waits behind: stops as SIGTTOU would, and returns without SA_RESTART,
/// so the set it interrupted fails with EINTR on each continue.
extern "C" fn stop_and_interrupt(sig: libc::c_int) {
    unsafe {
        let errno = *errno_location();
        stop_by(sig);
        libc::sigaction(sig, &action(stop_and_interrupt, 0), std::ptr::null_mut());
        *errno_location() = errno;
    }
}

/// The most a passphrase may be: what `--passphrase-stdin` takes (STM_CLI_PASSPHRASE_MAX).
pub const PASSPHRASE_MAX: usize = 255;

/// The terminal set for a passphrase: no echo, no canonical mode and no signal keys, so
/// that read_line, not the line discipline, decides what every key means. Set before
/// the label, and given back at once on every way out but success, where it stays held
/// without echo until the EchoHeld returned goes.
fn prompt_on(tty: File, label: &str) -> Result<(Zeroizing, EchoHeld)> {
    let fd = tty.as_raw_fd();
    let mut orig: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut orig) } != 0 {
        return Err(anyhow!("tcgetattr failed: {}", io::Error::last_os_error()));
    }
    let mut quiet = orig;
    quiet.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG | libc::IEXTEN);
    quiet.c_cc[libc::VMIN] = 1;
    quiet.c_cc[libc::VTIME] = 0;
    let held = match hold_terminal(fd, &quiet) {
        Ok(held) => held,
        Err(e) => {
            // It may have set the mode before it gave up.
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &orig) };
            return Err(e);
        }
    };

    // To /dev/tty, not stdout, which may be a pipe.
    let mut writer = &tty;
    let line = match writer.write_all(label.as_bytes()) {
        Ok(()) => {
            let mut reader = &tty;
            read_line(&mut reader)
        }
        Err(e) => Err(anyhow!(e).context("write prompt")),
    };

    // Cooked again, so the signal keys work while the key is derived, but with echo held
    // off until the caller lets go. TCSAFLUSH: what was typed past the end is not left
    // for the shell or the screen.
    let mut after = orig;
    if line.is_ok() {
        after.c_lflag &= !(libc::ECHO | libc::ECHONL);
    }
    while unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &after) } != 0
        && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
    {}
    // So the next line is not glued to the hidden input.
    let _ = writer.write_all(b"\n");
    // Caught before the mask goes back, so a stop that came meanwhile finds the handler.
    let caught = if line.is_ok() { catch_stops(fd, &orig, &after) } else { Vec::new() };
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &held, std::ptr::null_mut()) };
    line.map(|line| (line, EchoHeld { tty, orig, caught, given: false }))
}

/// Sets `quiet` and holds job control off until the terminal is given back, returning
/// the mask to restore: a stop sent from outside then lands with the terminal sane. Only
/// for the thread that reads, and the prompts run before the manager starts another.
/// TCSAFLUSH drops what was typed ahead, which the cooked terminal showed in clear. The
/// mode goes in before the block, so a caller in the background stops on SIGTTOU there,
/// as any program does, rather than set a terminal it is not in front of.
fn hold_terminal(fd: RawFd, quiet: &libc::termios) -> Result<libc::sigset_t> {
    let jobs = job_control_set();
    let off = libc::ECHO | libc::ICANON | libc::ISIG;
    for _ in 0..8 {
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, quiet) } != 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(anyhow!("tcsetattr disable-echo failed: {e}"));
        }
        let mut held: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &jobs, &mut held) };
        // A stop between the two, then `fg`, gives the terminal the shell's mode back.
        let mut now: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut now) } == 0 && now.c_lflag & off == 0 {
            return Ok(held);
        }
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &held, std::ptr::null_mut()) };
    }
    bail!("the terminal would not keep echo off for the passphrase")
}

/// One passphrase as Enter submits it, read from a terminal that edits nothing. The keys
/// mean what they mean in the screen's passphrase fields, so the same keys make the same
/// passphrase at either: Enter (CR or LF) submits; Backspace or Delete erases a
/// character; Ctrl-U erases them all; Ctrl-D, Ctrl-C and Ctrl-\ give up; Esc and the
/// sequence it starts (an arrow key, Alt with a key) and every other control key type
/// nothing. Past the limit nothing more is kept, and Enter refuses the line: refused at
/// once, the rest of it would be read, and shown, by whatever reads next. End-of-file,
/// which only a hangup gives, submits nothing.
pub(crate) fn read_line(src: &mut impl Read) -> Result<Zeroizing> {
    // Never grows, as what goes past the limit is not kept, and every way out of here wipes it.
    let mut buf = Zeroizing::new(Vec::with_capacity(PASSPHRASE_MAX + 1));
    let mut byte = [0u8; 1];
    let mut esc = Esc::None;
    // Characters typed past the limit, and whether the bytes now coming finish one.
    let (mut past, mut finishing_past) = (0usize, false);
    let ended = loop {
        let b = match src.read(&mut byte) {
            Ok(0) => break Err(anyhow!("the terminal closed at the passphrase prompt")),
            Ok(_) => byte[0],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => break Err(anyhow!("read tty: {e}")),
        };
        let (next, typed) = esc.step(b);
        esc = next;
        if !typed {
            continue;
        }
        let continuation = (0x80..=0xbf).contains(&b);
        if !continuation {
            finishing_past = false;
        }
        match b {
            b'\n' | b'\r' if past > 0 => break Err(anyhow!("passphrase exceeds {PASSPHRASE_MAX} bytes")),
            b'\n' | b'\r' => break Ok(()),
            0x7f | 0x08 if past > 0 => past -= 1,
            0x7f | 0x08 => erase_char(&mut buf.0),
            0x15 => {
                buf.0.clear();
                past = 0;
            }
            0x03 | 0x04 | 0x1c => break Err(anyhow!("the passphrase prompt was given up")),
            0x1b => esc = Esc::Start,
            0x00..=0x1f => {}
            _ if continuation && finishing_past => {}
            // A character goes in whole or not at all: never a lead byte without the rest.
            b if past > 0 || buf.len() + utf8_len(b) > PASSPHRASE_MAX => {
                past += 1;
                finishing_past = !continuation;
            }
            b => buf.0.push(b),
        }
    };
    unsafe { std::ptr::write_volatile(&mut byte[0], 0) };
    ended?;
    if buf.is_empty() {
        bail!("empty passphrase refused");
    }
    Ok(buf)
}

/// Where read_line is in an escape sequence, whose bytes type nothing.
#[derive(Clone, Copy)]
enum Esc {
    None,
    /// Just after Esc: `[` or `O` starts a sequence, a key there is Alt with that key.
    Start,
    /// After Esc `[`: parameters, then a final byte.
    Csi,
    /// After Esc `O`: one final byte.
    Ss3,
    /// The rest of a UTF-8 character typed with Alt.
    Rest(u8),
}

impl Esc {
    /// The state after `b`, and whether `b` is a key in its own right. A control byte
    /// ends a sequence and is a key, so Esc then Enter still submits.
    fn step(self, b: u8) -> (Esc, bool) {
        let control = b < 0x20 || b == 0x7f;
        match self {
            Esc::None => (Esc::None, true),
            _ if control => (Esc::None, true),
            Esc::Start => match b {
                b'[' => (Esc::Csi, false),
                b'O' => (Esc::Ss3, false),
                0xc0..=0xdf => (Esc::Rest(1), false),
                0xe0..=0xef => (Esc::Rest(2), false),
                0xf0..=0xf7 => (Esc::Rest(3), false),
                _ => (Esc::None, false),
            },
            Esc::Csi => match b {
                0x20..=0x3f => (Esc::Csi, false),
                0x40..=0x7e => (Esc::None, false),
                _ => (Esc::None, true),
            },
            Esc::Ss3 => (Esc::None, b >= 0x80),
            Esc::Rest(n) => match b {
                0x80..=0xbf if n > 1 => (Esc::Rest(n - 1), false),
                0x80..=0xbf => (Esc::None, false),
                _ => Esc::None.step(b),
            },
        }
    }
}

/// The bytes of the UTF-8 character `lead` starts; 1 for any other byte.
fn utf8_len(lead: u8) -> usize {
    match lead {
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1,
    }
}

/// Erases the last character: a UTF-8 one whole, as the screen's fields do, and any
/// other byte alone.
fn erase_char(buf: &mut Vec<u8>) {
    let tail = buf.iter().rev().take(3).take_while(|&&b| (0x80..=0xbf).contains(&b)).count();
    let keep = match buf.len().checked_sub(tail + 1) {
        Some(i) if tail > 0 && buf[i] >= 0xc0 => i,
        _ => buf.len().saturating_sub(1),
    };
    buf.truncate(keep);
}

#[cfg(test)]
mod prompt_tests {
    use super::*;
    use std::os::unix::io::{FromRawFd, RawFd};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    fn line(keys: &[u8]) -> Result<Vec<u8>> {
        read_line(&mut &keys[..]).map(|z| z.as_bytes().to_vec())
    }

    fn gave_up(keys: &[u8]) -> bool {
        matches!(line(keys), Err(e) if e.to_string().contains("given up"))
    }

    #[test]
    fn end_of_file_before_enter_submits_nothing() {
        let got = line(b"correct horse");
        assert!(matches!(&got, Err(e) if e.to_string().contains("closed")), "a hangup before Enter gave {:?}",
                got.map(|v| String::from_utf8_lossy(&v).into_owned()));
    }

    #[test]
    fn enter_is_either_return_or_line_feed() {
        assert_eq!(line(b"right\r").expect("CR submits"), b"right");
        assert_eq!(line(b"right\n").expect("LF submits"), b"right");
    }

    #[test]
    fn ctrl_u_clears_what_was_typed() {
        assert_eq!(line(b"wrong\x15right\n").expect("a passphrase"), b"right");
    }

    #[test]
    fn ctrl_d_ctrl_c_and_ctrl_backslash_give_up() {
        assert!(gave_up(b"half\x04"), "Ctrl-D");
        assert!(gave_up(b"half\x03"), "Ctrl-C");
        assert!(gave_up(b"half\x1c"), "Ctrl-\\");
    }

    #[test]
    fn delete_erases_a_whole_character() {
        assert_eq!(line(b"rigxht\x7f\x7f\x7fht\n").expect("a passphrase"), b"right");
        assert_eq!(line(b"caf\xc3\xa9\x7fe\n").expect("a passphrase"), b"cafe", "a two-byte character");
        assert_eq!(line(b"a\xf0\x9f\x94\x91\x08b\n").expect("a passphrase"), b"ab", "a four-byte one, by BS");
        assert_eq!(line(b"a\xa9\x7f\n").expect("a passphrase"), b"a", "a byte that starts no character");
    }

    #[test]
    fn escape_sequences_and_other_control_keys_type_nothing() {
        assert_eq!(line(b"ri\x1b[Dght\n").expect("an arrow key"), b"right");
        assert_eq!(line(b"ri\x1bOAght\n").expect("an SS3 arrow key"), b"right");
        assert_eq!(line(b"ri\x1b[1;5Cght\n").expect("Ctrl with an arrow key"), b"right");
        assert_eq!(line(b"ri\x1bxght\n").expect("Alt with a key"), b"right");
        assert_eq!(line(b"ri\x1b\xc3\xa9ght\n").expect("Alt with a two-byte key"), b"right");
        assert_eq!(line(b"\x1b[200~right\x1b[201~\n").expect("a bracketed paste"), b"right");
        assert_eq!(line(b"right\x1b\n").expect("Esc then Enter"), b"right");
        assert_eq!(line(b"ri\x17g\tht\x1a\x00\n").expect("Ctrl-W, Tab, Ctrl-Z, NUL"), b"right");
    }

    #[test]
    fn an_empty_line_and_one_past_the_limit_are_refused() {
        assert!(line(b"\n").is_err());
        let mut long = vec![b'a'; PASSPHRASE_MAX];
        long.push(b'\n');
        assert_eq!(line(&long).expect("the limit fits").len(), PASSPHRASE_MAX);
        long.insert(0, b'a');
        assert!(matches!(line(&long), Err(e) if e.to_string().contains("exceeds")));
    }

    #[test]
    fn past_the_limit_the_line_is_read_to_enter_then_refused() {
        let over = vec![b'a'; PASSPHRASE_MAX + 45];
        // Not refused at the limit: the rest is read, so the hangup is what ends it.
        assert!(matches!(line(&over), Err(e) if e.to_string().contains("closed")), "refused before the end");
        // What was erased past the limit goes first.
        let mut keys = over.clone();
        keys.extend_from_slice(&[0x7f; 45]);
        keys.push(b'\n');
        assert_eq!(line(&keys).expect("back at the limit").len(), PASSPHRASE_MAX);
        // Ctrl-U starts again.
        let mut keys = over.clone();
        keys.extend_from_slice(b"\x15ok\n");
        assert_eq!(line(&keys).expect("after Ctrl-U"), b"ok");
        // A character that does not fit whole is not kept in part.
        let mut keys = vec![b'a'; PASSPHRASE_MAX - 1];
        keys.extend_from_slice("\u{e9}\n".as_bytes());
        assert!(matches!(line(&keys), Err(e) if e.to_string().contains("exceeds")), "a lead byte alone was kept");
        let mut keys = vec![b'a'; PASSPHRASE_MAX - 1];
        keys.extend_from_slice("\u{e9}\x7f\n".as_bytes());
        assert_eq!(line(&keys).expect("the character erased").len(), PASSPHRASE_MAX - 1);
    }

    /// A pty whose fds no spawned child inherits, and whose output a thread reads: on
    /// macOS a TCSAFLUSH waits for the output to be read.
    struct Pty {
        master: File,
        slave: Option<File>,
        probe: RawFd,
        shown: Arc<Mutex<Vec<u8>>>,
    }

    impl Pty {
        fn new() -> Pty {
            let (mut m, mut s) = (0, 0);
            let rc = unsafe {
                libc::openpty(&mut m, &mut s, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
            };
            assert_eq!(rc, 0, "openpty: {}", io::Error::last_os_error());
            let probe = unsafe { libc::fcntl(s, libc::F_DUPFD_CLOEXEC, 0) };
            let out = unsafe { libc::fcntl(m, libc::F_DUPFD_CLOEXEC, 0) };
            assert!(probe >= 0 && out >= 0);
            for fd in [m, s] {
                assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) }, 0);
            }
            let shown = Arc::new(Mutex::new(Vec::new()));
            let into = shown.clone();
            std::thread::spawn(move || {
                let mut out = unsafe { File::from_raw_fd(out) };
                let mut chunk = [0u8; 256];
                while let Ok(n @ 1..) = out.read(&mut chunk) {
                    into.lock().unwrap().extend_from_slice(&chunk[..n]);
                }
            });
            let (master, slave) = unsafe { (File::from_raw_fd(m), File::from_raw_fd(s)) };
            Pty { master, slave: Some(slave), probe, shown }
        }

        fn lflag(&self) -> libc::tcflag_t {
            let mut t: libc::termios = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::tcgetattr(self.probe, &mut t) }, 0);
            t.c_lflag
        }

        fn wait_shown(&self, what: &[u8]) {
            let end = Instant::now() + Duration::from_secs(5);
            while !self.shown.lock().unwrap().windows(what.len()).any(|w| w == what) {
                assert!(Instant::now() < end, "{:?} was never shown", String::from_utf8_lossy(what));
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        /// Starts the prompt and waits for its mode.
        fn prompt(&mut self) -> std::sync::mpsc::Receiver<Result<(Vec<u8>, EchoHeld)>> {
            let slave = self.slave.take().expect("one prompt per pty");
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(prompt_on(slave, "P: ").map(|(z, held)| (z.as_bytes().to_vec(), held)));
            });
            let end = Instant::now() + Duration::from_secs(5);
            while self.lflag() & libc::ICANON != 0 {
                assert!(Instant::now() < end, "the prompt never turned canonical mode off");
                std::thread::sleep(Duration::from_millis(5));
            }
            rx
        }

        /// What a read of the slave would get now, canonical or not.
        fn left_unread(&self) -> Vec<u8> {
            let fl = unsafe { libc::fcntl(self.probe, libc::F_GETFL) };
            assert_eq!(unsafe { libc::fcntl(self.probe, libc::F_SETFL, fl | libc::O_NONBLOCK) }, 0);
            let mut got = vec![0u8; 64];
            let n = unsafe { libc::read(self.probe, got.as_mut_ptr().cast(), got.len()) };
            got.truncate(n.max(0) as usize);
            got
        }
    }

    impl Drop for Pty {
        fn drop(&mut self) {
            unsafe { libc::close(self.probe) };
        }
    }

    /// Keys sent only once the mode is set reach read_line as typed, Ctrl-C among them,
    /// and the terminal is given back as it was.
    #[test]
    fn on_a_terminal_the_mode_is_set_for_the_keys_and_restored_after() {
        let mut pty = Pty::new();
        let before = pty.lflag();
        assert_ne!(before & libc::ICANON, 0, "a fresh pty starts canonical");
        assert_ne!(before & libc::ISIG, 0, "and with signal keys");
        let rx = pty.prompt();
        let now = pty.lflag();
        assert_eq!(now & libc::ECHO, 0, "the passphrase would be echoed");
        assert_eq!(now & libc::ISIG, 0, "Ctrl-C would be a signal, not a key");
        // With signal keys on, the line discipline would take Ctrl-C and read_line
        // would never see it.
        pty.master.write_all(b"half\x03").expect("type");
        let got = rx.recv_timeout(Duration::from_secs(5)).expect("Ctrl-C never reached the prompt");
        assert!(matches!(&got, Err(e) if e.to_string().contains("given up")), "Ctrl-C gave {:?}",
                got.map(|(v, _)| v.len()));
        // The settings it changed; the kernel's own state bits (PENDIN on macOS) may differ.
        let set = libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN;
        assert_eq!(pty.lflag() & set, before & set, "the terminal was not given back as it was");
    }

    /// Typed before the prompt, while the terminal still showed keys, is not passphrase.
    #[test]
    fn what_was_typed_ahead_is_dropped() {
        let mut pty = Pty::new();
        pty.master.write_all(b"ahead").expect("type ahead");
        // Its echo means the line discipline holds it.
        pty.wait_shown(b"ahead");
        let rx = pty.prompt();
        pty.master.write_all(b"right\n").expect("type");
        let got = rx.recv_timeout(Duration::from_secs(5)).expect("the prompt never returned");
        assert_eq!(got.expect("a passphrase").0, b"right", "the type-ahead became part of it");
    }

    /// What came after Enter is not left for the next reader of the terminal.
    #[test]
    fn what_was_typed_past_enter_is_dropped() {
        let mut pty = Pty::new();
        let rx = pty.prompt();
        pty.master.write_all(b"right\ntail\n").expect("type");
        let got = rx.recv_timeout(Duration::from_secs(5)).expect("the prompt never returned");
        let (pass, held) = got.expect("a passphrase");
        assert_eq!(pass, b"right");
        let left = pty.left_unread();
        assert!(left.is_empty(), "{:?} was left for the next reader", String::from_utf8_lossy(&left));
        drop(held);
    }

    /// After Enter, while the key is derived: cooked, so the signal keys work, but nothing
    /// typed is shown, and it is dropped when the terminal is let go, given back whole.
    #[test]
    fn echo_stays_off_until_the_terminal_is_let_go() {
        let mut pty = Pty::new();
        let before = pty.lflag();
        let rx = pty.prompt();
        pty.master.write_all(b"right\n").expect("type");
        let got = rx.recv_timeout(Duration::from_secs(5)).expect("the prompt never returned");
        let (_, held) = got.expect("a passphrase");
        let now = pty.lflag();
        assert_eq!(now & libc::ECHO, 0, "keys typed while the key is derived would be shown");
        assert_ne!(now & libc::ICANON, 0, "not cooked again");
        assert_ne!(now & libc::ISIG, 0, "the signal keys are off while the key is derived");
        pty.master.write_all(b"during\n").expect("type");
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let mut n: libc::c_int = 0;
            assert_eq!(unsafe { libc::ioctl(pty.probe, libc::FIONREAD, &mut n) }, 0);
            if n > 0 {
                break;
            }
            assert!(Instant::now() < end, "the line typed during the wait never arrived");
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(Duration::from_millis(100));
        let shown = String::from_utf8_lossy(&pty.shown.lock().unwrap()).into_owned();
        assert!(!shown.contains("during"), "shown while the key was derived: {shown:?}");
        // Not this process's controlling terminal, so no job is in front of it: dropped, the
        // hold would leave it alone; given back, it restores it.
        held.give_back(|| false);
        let set = libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN;
        assert_eq!(pty.lflag() & set, before & set, "the terminal was not given back as it was");
        let left = pty.left_unread();
        assert!(left.is_empty(), "{:?} outlived the wait", String::from_utf8_lossy(&left));
        // The control: with echo back, a key is shown.
        pty.master.write_all(b"after").expect("type");
        pty.wait_shown(b"after");
    }

    /// Two holds at once, as the tests here make: the second takes none of the handlers,
    /// and they keep the first's terminal.
    #[test]
    fn a_second_hold_does_not_take_hold() {
        let t: libc::termios = unsafe { std::mem::zeroed() };
        // Never opened: the handlers would set them only on a stop or a continue, in front.
        let (one, two) = (1000, 1001);
        let end = Instant::now() + Duration::from_secs(10);
        let first = loop {
            let caught = catch_stops(one, &t, &t);
            if !caught.is_empty() {
                break caught;
            }
            assert!(Instant::now() < end, "no hold took the handlers: another kept them, or a stop is not at its default");
            std::thread::sleep(Duration::from_millis(5));
        };
        let second = catch_stops(two, &t, &t);
        let fd = HOLD.fd.load(Ordering::Acquire);
        for (sig, old) in first {
            unsafe { libc::sigaction(sig, &old, std::ptr::null_mut()) };
        }
        HOLD.fd.store(FREE, Ordering::Release);
        assert!(second.is_empty(), "a second hold took {} handlers", second.len());
        assert_eq!(fd, one, "a second hold pointed the handlers at its terminal");
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
