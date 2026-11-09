//! A daemon the manager started must not outlive it: after a kill, a crash or
//! a closed terminal, a volume would stay unlocked and served with nobody in
//! front of it. The manager holds the write end of a pipe for as long as it
//! lives and each daemon reads the other end, so the read returning means the
//! manager is gone, however that happened. No signal handler can promise that,
//! because SIGKILL runs none.

use anyhow::{bail, Result};
use std::sync::OnceLock;
use std::time::Duration;

const ENV: &str = "STRATUM_LIFELINE_FD";

/// How long a daemon asked to stop has to unmount before it is killed: its last
/// commit happens on the way out, and a stop that never ends would leave the
/// volume served and unlocked with nobody in front of it.
pub const STOP_DEADLINE: Duration = Duration::from_secs(30);

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
    watch(fd, STOP_DEADLINE);
}

/// Once the manager has gone, nobody is left to give the SIGKILL that stop_child
/// gives a daemon whose stop does not end, so the daemon gives it to itself.
fn watch(fd: i32, deadline: Duration) {
    std::thread::spawn(move || {
        let mut byte = 0u8;
        loop {
            let n = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                eprintln!("stratum: reading {ENV} failed ({e}); this daemon will not stop with its manager");
                return;
            }
            break;
        }
        unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
        std::thread::sleep(deadline);
        unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
    });
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const CHILD: &str = "STRATUM_LIFELINE_TEST_CHILD";

    /// Run only as the child below: a daemon whose SIGTERM never ends it, and
    /// whose manager goes.
    #[test]
    fn lifeline_child_role() {
        if std::env::var_os(CHILD).is_none() {
            return;
        }
        unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        super::watch(fds[0], Duration::from_millis(300));
        unsafe { libc::close(fds[1]) };
        std::thread::sleep(Duration::from_secs(20));
    }

    #[test]
    fn a_daemon_whose_stop_never_ends_is_killed_once_its_manager_has_gone() {
        let me = std::env::current_exe().expect("the test binary");
        let mut child = Command::new(me)
            .args(["lifeline::tests::lifeline_child_role", "--exact", "--test-threads=1"])
            .env(CHILD, "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the child role");
        let end = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(s) = child.try_wait().expect("wait for the child role") {
                break Some(s);
            }
            if Instant::now() > end {
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        if status.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
        assert_eq!(status.and_then(|s| s.signal()), Some(libc::SIGKILL),
                   "a daemon that ignored its SIGTERM outlived its manager: {status:?}");
    }
}
