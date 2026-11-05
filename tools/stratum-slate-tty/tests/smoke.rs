//! End-to-end smoke test: spawn stratum-slate, dial it via SlateClient,
//! exercise read + write paths.
//!
//! Skipped in CI when the slate binary isn't built; the test discovers
//! the binary via `STM_BUILD_DIR` (set by the cmake-driven CI harness)
//! or falls back to `../../build/src/cmd/stratum-slate/stratum-slate`.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

mod harness {
    use super::*;
    use std::io::Write as _;

    pub struct DaemonGuard {
        pub child: Child,
        pub sock: PathBuf,
    }
    impl Drop for DaemonGuard {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_file(&self.sock);
        }
    }

    pub fn locate_slate_binary() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("STM_BUILD_DIR") {
            let candidate = PathBuf::from(p)
                .join("src/cmd/stratum-slate/stratum-slate");
            if candidate.exists() {
                return Some(candidate);
            }
        }
        for rel in [
            "../../build/src/cmd/stratum-slate/stratum-slate",
            "../../../build/src/cmd/stratum-slate/stratum-slate",
        ] {
            let p = PathBuf::from(rel);
            if p.exists() {
                return Some(p.canonicalize().unwrap_or(p));
            }
        }
        None
    }

    pub fn spawn_slate() -> DaemonGuard {
        let bin = locate_slate_binary()
            .expect("slate daemon binary not found — set STM_BUILD_DIR or run `cmake --build build`");
        let test_id = NEXT_TEST_ID.fetch_add(1, Ordering::SeqCst);
        let sock = std::env::temp_dir()
            .join(format!("stratum-slate-tty-test-{}-{}.sock", std::process::id(), test_id));
        let _ = std::fs::remove_file(&sock);
        let child = Command::new(&bin)
            .args([
                "serve",
                "--listen",
                sock.to_str().unwrap(),
                "--allow-unauth",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn stratum-slate");
        // Wait for the socket to appear.
        for _ in 0..200 {
            if sock.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        DaemonGuard { child, sock }
    }

    /// Discover libstm_9p_client search path (mirrors build.rs logic
    /// for tests run via `cargo test` from the crate root).
    pub fn ensure_lib_built() {
        // build.rs already linked; this is a sanity-check no-op.
        std::io::stderr().flush().ok();
    }
}

#[path = "../src/ffi.rs"]
mod ffi;
#[path = "../src/slate.rs"]
mod slate;

use slate::{read_lines, read_text_trim, SlateClient};

#[test]
fn smoke_dial_and_read_version() {
    harness::ensure_lib_built();
    let g = harness::spawn_slate();
    let mut c = SlateClient::dial(&g.sock).expect("dial slate");
    let v: u64 = read_text_trim(&mut c, "/version")
        .expect("read /version")
        .parse()
        .expect("parse version");
    assert!(v >= 1);
}

#[test]
fn smoke_read_panel_entries_when_disconnected() {
    let g = harness::spawn_slate();
    let mut c = SlateClient::dial(&g.sock).expect("dial slate");
    // No backend attached; entries should be empty.
    let entries = read_lines(&mut c, "/panels/left/entries").expect("read entries");
    assert!(entries.is_empty(), "got {} entries", entries.len());
    let path = read_text_trim(&mut c, "/panels/left/path").expect("read path");
    // Disconnected: just '\n' which read_text_trim strips → empty.
    assert_eq!(path, "");
}

#[test]
fn smoke_write_event_bumps_version() {
    let g = harness::spawn_slate();
    let mut c = SlateClient::dial(&g.sock).expect("dial slate");
    let v0: u64 = read_text_trim(&mut c, "/version")
        .unwrap()
        .parse()
        .unwrap();
    c.write_path("/event", b"hello slate-tty\n").expect("write event");
    let v1: u64 = read_text_trim(&mut c, "/version")
        .unwrap()
        .parse()
        .unwrap();
    assert!(v1 > v0, "version should bump (v0={v0} v1={v1})");
}

#[test]
fn smoke_write_panel_action_unknown_verb_errors() {
    let g = harness::spawn_slate();
    let mut c = SlateClient::dial(&g.sock).expect("dial slate");
    // Unknown verb returns STM_ENOTSUPPORTED → write fails. The TUI
    // uppercase-tolerates this; we verify the wrapper surfaces an Err.
    let r = c.write_path("/panels/left/action", b"key Quux\n");
    assert!(r.is_err(), "expected error for unknown verb");
}

#[test]
fn smoke_redraw_returns_immediately_when_already_advanced() {
    // Probe: with offset = 0 and current_version >= 1, /redraw should
    // return immediately without blocking. Validates the protocol +
    // our redraw_once parse path.
    let g = harness::spawn_slate();
    let mut c = SlateClient::dial(&g.sock).expect("dial");
    let v0: u64 = read_text_trim(&mut c, "/version").unwrap().parse().unwrap();
    assert!(v0 >= 1);
    let v_got = c.redraw_once(0).expect("redraw_once");
    assert_eq!(v_got, Some(v0));
}

#[test]
fn smoke_redraw_blocks_then_wakes() {
    // Concurrency test mirroring test_slate_socket.c's
    // slate_socket_redraw_wakes_on_event_from_other_connection:
    // a reader thread blocks on /redraw with offset=current_version;
    // the main thread writes /event from a different connection,
    // which bumps version and should wake the reader.
    let g = harness::spawn_slate();
    // First learn the current version (1 right after spawn).
    let v0 = {
        let mut c = SlateClient::dial(&g.sock).expect("dial probe");
        let v: u64 = read_text_trim(&mut c, "/version")
            .unwrap()
            .parse()
            .unwrap();
        v
    };
    let sock = g.sock.clone();
    let reader = thread::spawn(move || {
        let mut c = SlateClient::dial(&sock).expect("dial reader");
        c.redraw_once(v0)
    });
    // Give reader time to dial + walk + lopen + enter blocking read.
    thread::sleep(Duration::from_millis(150));
    // Now write /event from the main thread → wakes reader.
    let mut writer = SlateClient::dial(&g.sock).expect("dial writer");
    writer.write_path("/event", b"wakeup\n").expect("write event");
    let result = reader.join().unwrap().expect("reader redraw_once");
    let v1 = result.expect("reader should observe a new version");
    assert!(v1 > v0, "reader saw v1={v1}, expected > v0={v0}");
}
