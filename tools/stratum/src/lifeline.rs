//! A daemon the manager started must not outlive it: after a kill, a crash or
//! a closed terminal, a volume would stay unlocked and served with nobody in
//! front of it. The manager holds the write end of a pipe for as long as it
//! lives and each daemon reads the other end, so the read returning means the
//! manager is gone, however that happened. No signal handler can promise that,
//! because SIGKILL runs none.

use anyhow::{bail, Result};
use std::sync::OnceLock;

const ENV: &str = "STRATUM_LIFELINE_FD";

static READ_END: OnceLock<i32> = OnceLock::new();

/// In the manager, before it spawns anything. The write end is close-on-exec
/// and never closed, so only this process ending closes it.
pub fn hold() -> Result<()> {
    if READ_END.get().is_some() {
        return Ok(());
    }
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        bail!("lifeline pipe: {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        bail!("lifeline pipe: {}", std::io::Error::last_os_error());
    }
    let _ = READ_END.set(fds[0]);
    Ok(())
}

/// For each daemon's Command, and only those: a program the manager starts for
/// any other reason has no use for the number, and passing it on could give it
/// to a daemon that was never the manager's.
pub fn env() -> Option<(&'static str, String)> {
    READ_END.get().map(|fd| (ENV, fd.to_string()))
}

/// In a daemon, before it starts serving. Ends this process through its own
/// SIGTERM handling, which unmounts cleanly, once the manager is gone. A daemon
/// started by hand has no such variable and is left alone.
pub fn follow() {
    let Some(fd) = std::env::var(ENV).ok().and_then(|v| v.parse::<i32>().ok()) else {
        return;
    };
    std::env::remove_var(ENV);
    // A number that names something else must not be read from, and failing to
    // read it does not mean the manager has gone.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let is_pipe = unsafe { libc::fstat(fd, &mut st) } == 0 && st.st_mode & libc::S_IFMT == libc::S_IFIFO;
    if !is_pipe {
        eprintln!("stratum: {ENV}={fd} is not a pipe; this daemon will not stop with its manager");
        return;
    }
    std::thread::spawn(move || {
        let mut byte = 0u8;
        loop {
            let n = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
    });
}
