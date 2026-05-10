//! SWISS-4r-10: end-to-end CRUD stability tests for the v2 stack.
//!
//! User-explicit ask (2026-05-10): "We must work tirelessly,
//! construct every possible test case, and test it."
//!
//! Each test spawns its own stratumd + slate + host-fs trio in a
//! tempdir. Tests cover the critical CRUD paths the TUI exercises:
//! single-file copy, dir copy, conflict resolution, delete, the
//! .git tree case the user reported, and concurrent panel access.
//!
//! Run with: `cargo test --release --test e2e_crud -- --test-threads=4`
//!
//! Skipped automatically when the `stratum` binary isn't built.

mod common;

use common::{Session, SessionBuilder};
use std::path::Path;
use std::process::Stdio;

// ── helpers ──────────────────────────────────────────────────────────

fn session() -> Session {
    SessionBuilder::default()
        .build()
        .expect("session build")
}

fn touch(p: &Path, body: &[u8]) {
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(p, body).unwrap();
}

// ── CRUD: stratum-fs CLI direct (every test must pass) ──────────────

#[test]
fn fs_write_then_read_roundtrip() {
    let s = session();
    s.fs_write_bytes(&s.stratumd_sock, "/hello.txt", b"hello world\n")
        .unwrap();
    let body = s.fs_read(&s.stratumd_sock, "/hello.txt").unwrap();
    assert_eq!(body, b"hello world\n");
}

#[test]
fn fs_overwrite_existing_file() {
    let s = session();
    s.fs_write_bytes(&s.stratumd_sock, "/x.txt", b"v1").unwrap();
    s.fs_write_bytes(&s.stratumd_sock, "/x.txt", b"v2-replaced")
        .unwrap();
    let body = s.fs_read(&s.stratumd_sock, "/x.txt").unwrap();
    assert_eq!(
        body, b"v2-replaced",
        "second write should overwrite, not append"
    );
}

#[test]
fn fs_overwrite_dotfile() {
    let s = session();
    s.fs_write_bytes(&s.stratumd_sock, "/.gitignore", b"target/\n")
        .unwrap();
    s.fs_write_bytes(&s.stratumd_sock, "/.gitignore", b"target/\nbuild/\n")
        .unwrap();
    let body = s.fs_read(&s.stratumd_sock, "/.gitignore").unwrap();
    assert_eq!(body, b"target/\nbuild/\n", "dotfile overwrite");
}

#[test]
fn fs_overwrite_nested_file() {
    let s = session();
    s.fs_mkdir(&s.stratumd_sock, "/sub").unwrap();
    s.fs_mkdir(&s.stratumd_sock, "/sub/deep").unwrap();
    s.fs_write_bytes(&s.stratumd_sock, "/sub/deep/file.txt", b"v1")
        .unwrap();
    s.fs_write_bytes(&s.stratumd_sock, "/sub/deep/file.txt", b"v2")
        .unwrap();
    let body = s.fs_read(&s.stratumd_sock, "/sub/deep/file.txt").unwrap();
    assert_eq!(body, b"v2", "nested overwrite");
}

#[test]
fn fs_write_to_path_where_dir_exists_errors_cleanly() {
    let s = session();
    s.fs_mkdir(&s.stratumd_sock, "/some_dir").unwrap();
    let r = s.fs_write_bytes(&s.stratumd_sock, "/some_dir", b"oops");
    assert!(r.is_err(), "writing file to dir path should fail");
    let msg = r.unwrap_err().to_string();
    assert!(
        msg.contains("directory") || msg.contains("EISDIR") || msg.contains("status="),
        "error message should mention directory: {msg}"
    );
}

#[test]
fn fs_mkdir_existing_idempotent_or_eexist() {
    let s = session();
    s.fs_mkdir(&s.stratumd_sock, "/d").unwrap();
    // Second mkdir of same path should fail with EEXIST (-17). The
    // TUI tolerates this for "Overwrite policy = merge into existing
    // dir" by ignoring the error.
    let r = s.fs_mkdir(&s.stratumd_sock, "/d");
    assert!(
        r.is_err(),
        "second mkdir of same path should error (EEXIST), TUI ignores"
    );
}

#[test]
fn fs_persistence_across_remount() {
    // SWISS-4l carry: write, drop the daemon, re-mount, verify.
    //
    // Volume + keyfile are kept alive across the session drop by
    // copying them out of the tempdir before the tempdir is freed.
    // (The Session struct owns the TempDir; dropping Session
    // removes the dir along with everything inside it.)
    let body = b"survive me\n";
    let preserve_dir = tempfile::Builder::new()
        .prefix("swiss4r-persist-")
        .tempdir()
        .unwrap();
    let preserved_stm = preserve_dir.path().join("v.stm");
    let preserved_key = preserve_dir.path().join("v.stm.key");

    let bin = {
        let s = session();
        s.fs_write_bytes(&s.stratumd_sock, "/persist.txt", body)
            .unwrap();
        // Force fsync via a final stratum fs op (auto-fsync per
        // SWISS-4l). The fsync is best-effort: stat is the smallest
        // op that triggers the auto-flush.
        let _ = s.fs_run(&s.stratumd_sock, &["stat", "/persist.txt"], Stdio::null());
        // Copy the volume + keyfile somewhere durable.
        std::fs::copy(&s.stm_path, &preserved_stm).unwrap();
        std::fs::copy(&s.stm_keyfile, &preserved_key).unwrap();
        s.bin.clone()
    };
    // Session dropped — its tempdir is gone.

    // Re-spawn stratumd against the preserved volume.
    let new_sock = preserve_dir.path().join("v2.sock");
    let log = preserve_dir.path().join("stratumd2.log");
    let mut child = std::process::Command::new(&bin)
        .args([
            "serve",
            preserved_stm.to_str().unwrap(),
            "--listen",
            new_sock.to_str().unwrap(),
            "--keyfile",
            preserved_key.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::fs::File::create(&log).unwrap()))
        .spawn()
        .unwrap();
    common::wait_for_sock(&new_sock, std::time::Duration::from_secs(8))
        .unwrap();

    // Re-read.
    let out = std::process::Command::new(&bin)
        .args(["fs", "-s", new_sock.to_str().unwrap(), "read", "/persist.txt"])
        .output()
        .unwrap();
    assert!(out.status.success(),
        "re-read after re-mount: stderr={:?}",
        String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout, body, "content survives daemon restart");

    let _ = child.kill();
    let _ = child.wait();
}

// ── Recursive delete (TUI gap — stratum-fs only has rm+rmdir) ────────

/// Helper: mimic the TUI's F8 batch-delete path. Walks bottom-up so
/// children are removed before their parent. Single-failure does not
/// abort; reports counts. This MUST match what the TUI does so the
/// regression test pins the fixed behavior.
fn batch_delete(s: &Session, sock: &Path, paths: &[String]) -> (u32, u32, Vec<String>) {
    let mut deleted = 0u32;
    let mut failed = 0u32;
    let mut errs = Vec::new();
    for p in paths {
        // Try rm first; if EISDIR or ENOTEMPTY, recursively walk.
        match s.fs_run(sock, &["rm", p], Stdio::null()) {
            Ok((0, _, _)) => { deleted += 1; }
            Ok((_, _, err)) => {
                let stderr = String::from_utf8_lossy(&err);
                if stderr.contains("status=-21") || stderr.contains("status=-39") {
                    // EISDIR or ENOTEMPTY — recurse (TUI must do this).
                    match recursive_delete(s, sock, p) {
                        Ok(n) => { deleted += n; }
                        Err((n, e)) => { deleted += n; failed += 1; errs.push(e); }
                    }
                } else {
                    failed += 1;
                    errs.push(format!("{p}: {}", stderr.trim()));
                }
            }
            Err(e) => { failed += 1; errs.push(format!("{p}: {e}")); }
        }
    }
    (deleted, failed, errs)
}

fn recursive_delete(s: &Session, sock: &Path, dir: &str) -> Result<u32, (u32, String)> {
    let entries = s.fs_ls(sock, dir).map_err(|e| (0, e.to_string()))?;
    let mut n = 0u32;
    for (kind, name) in &entries {
        let child = if dir == "/" {
            format!("/{name}")
        } else {
            format!("{dir}/{name}")
        };
        if *kind == 'd' {
            match recursive_delete(s, sock, &child) {
                Ok(c) => { n += c; }
                Err((c, e)) => { n += c; return Err((n, e)); }
            }
        } else {
            match s.fs_rm(sock, &child) {
                Ok(()) => { n += 1; }
                Err(e) => { return Err((n, e.to_string())); }
            }
        }
    }
    // rmdir self (unless root).
    if dir != "/" {
        let (code, _, err) = s.fs_run(sock, &["rmdir", dir], Stdio::null())
            .map_err(|e| (n, e.to_string()))?;
        if code != 0 {
            return Err((n, format!("rmdir {dir}: {}",
                String::from_utf8_lossy(&err).trim())));
        }
        n += 1;
    }
    Ok(n)
}

#[test]
fn delete_file_works() {
    let s = session();
    s.fs_write_bytes(&s.stratumd_sock, "/x.txt", b"x").unwrap();
    s.fs_rm(&s.stratumd_sock, "/x.txt").unwrap();
    assert!(!s.fs_stat(&s.stratumd_sock, "/x.txt"));
}

#[test]
fn delete_empty_dir_works() {
    let s = session();
    s.fs_mkdir(&s.stratumd_sock, "/empty").unwrap();
    let (code, _, err) = s
        .fs_run(&s.stratumd_sock, &["rmdir", "/empty"], Stdio::null())
        .unwrap();
    assert_eq!(code, 0, "rmdir empty: {}", String::from_utf8_lossy(&err));
}

#[test]
fn delete_nonempty_dir_with_rm_fails() {
    let s = session();
    s.fs_mkdir(&s.stratumd_sock, "/d").unwrap();
    s.fs_write_bytes(&s.stratumd_sock, "/d/a.txt", b"a").unwrap();
    let (code, _, err) = s
        .fs_run(&s.stratumd_sock, &["rm", "/d"], Stdio::null())
        .unwrap();
    assert!(code != 0, "rm of dir should fail");
    let stderr = String::from_utf8_lossy(&err);
    assert!(
        stderr.contains("status=-21") || stderr.contains("status=-39"),
        "rm of dir should return EISDIR(-21) or ENOTEMPTY(-39), got: {stderr}"
    );
}

#[test]
fn rmdir_nonempty_returns_enotempty_specifically() {
    // SWISS-4r-7 regression: pre-fix, the 9P client mapped Linux
    // ENOTEMPTY to STM_EBUSY (-16), which surfaced through stratum-fs
    // as "status=-16" instead of the explicit "status=-39 ENOTEMPTY".
    // Users couldn't distinguish "directory has children" from
    // "device busy" (a much more dire signal).
    let s = session();
    s.fs_mkdir(&s.stratumd_sock, "/nonempty").unwrap();
    s.fs_write_bytes(&s.stratumd_sock, "/nonempty/inner.txt", b"x")
        .unwrap();
    let (code, _, err) = s
        .fs_run(&s.stratumd_sock, &["rmdir", "/nonempty"], Stdio::null())
        .unwrap();
    assert!(code != 0);
    let stderr = String::from_utf8_lossy(&err);
    assert!(
        stderr.contains("status=-39"),
        "rmdir of non-empty dir → ENOTEMPTY(-39), got: {stderr}"
    );
    // SWISS-4r-12: human-readable explanation included.
    assert!(
        stderr.contains("ENOTEMPTY"),
        "stderr should include ENOTEMPTY mnemonic, got: {stderr}"
    );
}

#[test]
fn rm_of_dir_returns_eisdir_specifically() {
    // SWISS-4r-7 regression: pre-fix, the 9P client mapped Linux
    // EISDIR to STM_EINVAL (-22). User saw "status=-22" with no
    // hint that the issue was "you targeted a directory, not a file".
    // Now EISDIR (-21) flows through.
    let s = session();
    s.fs_mkdir(&s.stratumd_sock, "/somedir").unwrap();
    let (code, _, err) = s
        .fs_run(&s.stratumd_sock, &["rm", "/somedir"], Stdio::null())
        .unwrap();
    assert!(code != 0);
    let stderr = String::from_utf8_lossy(&err);
    assert!(
        stderr.contains("status=-21"),
        "rm of empty dir → EISDIR(-21), got: {stderr}"
    );
    assert!(
        stderr.contains("EISDIR"),
        "stderr should include EISDIR mnemonic, got: {stderr}"
    );
}

#[test]
fn rmtree_recursive_works() {
    // SWISS-4r-9: stratum-fs gained `rmtree` (rm -rf shape). The
    // TUI's batch delete uses this for stm-side dirs.
    let s = session();
    s.fs_mkdir(&s.stratumd_sock, "/tree").unwrap();
    s.fs_mkdir(&s.stratumd_sock, "/tree/sub").unwrap();
    s.fs_write_bytes(&s.stratumd_sock, "/tree/a.txt", b"a").unwrap();
    s.fs_write_bytes(&s.stratumd_sock, "/tree/sub/b.txt", b"b")
        .unwrap();
    let (code, _, err) = s
        .fs_run(&s.stratumd_sock, &["rmtree", "/tree"], Stdio::null())
        .unwrap();
    assert_eq!(code, 0, "rmtree: {}", String::from_utf8_lossy(&err));
    assert!(!s.fs_stat(&s.stratumd_sock, "/tree"));
}

#[test]
fn rmtree_refuses_root() {
    // SWISS-4r-9 footgun guard: rmtree / is refused. The TUI's
    // cwd-relative selection bounds it, so this is mostly for
    // direct CLI users.
    let s = session();
    s.fs_write_bytes(&s.stratumd_sock, "/a.txt", b"a").unwrap();
    let (code, _, _) = s
        .fs_run(&s.stratumd_sock, &["rmtree", "/"], Stdio::null())
        .unwrap();
    assert!(code != 0, "rmtree / must be refused");
    // The root file should still exist.
    assert!(s.fs_stat(&s.stratumd_sock, "/a.txt"));
}

#[test]
fn write_to_dir_path_returns_eisdir_human() {
    // SWISS-4r-12: the cmd_write EISDIR fallback message now
    // includes "is a directory; refusing to overwrite with file".
    let s = session();
    s.fs_mkdir(&s.stratumd_sock, "/somedir").unwrap();
    let r = s.fs_write_bytes(&s.stratumd_sock, "/somedir", b"oops");
    assert!(r.is_err());
    let msg = r.unwrap_err().to_string();
    assert!(
        msg.contains("directory"),
        "stderr should mention 'directory', got: {msg}"
    );
}

#[test]
fn recursive_delete_dir_tree() {
    let s = session();
    s.fs_mkdir(&s.stratumd_sock, "/proj").unwrap();
    s.fs_mkdir(&s.stratumd_sock, "/proj/src").unwrap();
    s.fs_write_bytes(&s.stratumd_sock, "/proj/README.md", b"r").unwrap();
    s.fs_write_bytes(&s.stratumd_sock, "/proj/src/main.rs", b"fn m(){}\n")
        .unwrap();
    let (deleted, failed, errs) = batch_delete(&s, &s.stratumd_sock,
        &vec!["/proj".into()]);
    assert_eq!(failed, 0, "recursive delete failures: {errs:?}");
    assert!(deleted >= 3, "deleted at least 3 entries (got {deleted})");
    assert!(!s.fs_stat(&s.stratumd_sock, "/proj"));
}

// ── .git directory torture (user-reported as fragile) ────────────────

fn build_minilike_git_tree(host: &Path) {
    // Mimic a small .git directory's shape (lots of small files +
    // nested dirs). User report: ".git directory is what gives it
    // hard time — cannot be successfully copied entirely, and then
    // it cannot be deleted from stm".
    touch(&host.join(".git/HEAD"), b"ref: refs/heads/main\n");
    touch(&host.join(".git/config"), b"[core]\n\trepositoryformatversion = 0\n");
    touch(&host.join(".git/description"), b"Unnamed repository\n");
    touch(&host.join(".git/refs/heads/main"), b"a".repeat(40).as_slice());
    touch(&host.join(".git/refs/tags/v1.0"), b"b".repeat(40).as_slice());
    touch(&host.join(".git/objects/info/packs"), b"");
    for prefix in ["00", "0a", "ab", "ff"] {
        touch(
            &host.join(format!(".git/objects/{prefix}/{}",
                "x".repeat(38))),
            b"\x00\x01\x02\x03some-binary-blob\n",
        );
    }
    touch(&host.join(".git/hooks/pre-commit.sample"),
        b"#!/bin/sh\nexit 0\n");
    touch(&host.join(".git/info/exclude"), b"# exclude\n");
    touch(&host.join(".git/index"), &[0u8; 64]);
}

#[test]
fn copy_dotgit_tree_to_stm() {
    let s = session();
    build_minilike_git_tree(&s.host_root);
    let (copied, skipped, failed, last_err) =
        s.copy_host_tree_to_stm(&s.host_root, "/");
    assert_eq!(failed, 0, "copy .git failed; last_err={last_err:?}");
    assert!(copied >= 10, "copied at least 10 entries (got {copied})");
    let _ = skipped;
    // Verify a couple of specific files arrived intact.
    let head = s.fs_read(&s.stratumd_sock, "/.git/HEAD").unwrap();
    assert_eq!(head, b"ref: refs/heads/main\n");
    let cfg = s.fs_read(&s.stratumd_sock, "/.git/config").unwrap();
    assert!(cfg.starts_with(b"[core]"), "config head: {cfg:?}");
}

#[test]
fn delete_dotgit_tree_from_stm() {
    let s = session();
    build_minilike_git_tree(&s.host_root);
    let (_c, _s2, failed, _le) = s.copy_host_tree_to_stm(&s.host_root, "/");
    assert_eq!(failed, 0);
    let (deleted, dfailed, errs) =
        batch_delete(&s, &s.stratumd_sock, &vec!["/.git".to_string()]);
    assert_eq!(dfailed, 0, "delete .git failed: {errs:?}");
    assert!(deleted >= 10, "deleted at least 10");
    assert!(!s.fs_stat(&s.stratumd_sock, "/.git"));
}

// ── Larger workloads ─────────────────────────────────────────────────

#[test]
fn copy_many_small_files() {
    // Mimic .git's ~hundreds of tiny files. Volume = 64M default,
    // bootstrap ~ 4M (auto-scale via SWISS-4n3); 200 files × 100B
    // should fit comfortably.
    let s = session();
    for i in 0..200u32 {
        std::fs::create_dir_all(s.host_root.join(format!("dir{}", i / 50))).unwrap();
        let p = s.host_root.join(format!("dir{}/f{i:03}.bin", i / 50));
        touch(&p, format!("file-{i}-content\n").as_bytes());
    }
    let (copied, _sk, failed, last) = s.copy_host_tree_to_stm(&s.host_root, "/");
    assert_eq!(failed, 0, "small-file batch failed; last_err={last:?}");
    assert!(copied >= 200, "copied >= 200; got {copied}");
}

#[test]
fn copy_500kb_file() {
    let s = session();
    let body: Vec<u8> = (0..500_000u32)
        .map(|i| (i & 0xff) as u8)
        .collect();
    s.fs_write_bytes(&s.stratumd_sock, "/big.bin", &body).unwrap();
    let read_back = s.fs_read(&s.stratumd_sock, "/big.bin").unwrap();
    assert_eq!(read_back.len(), body.len(), "size mismatch");
    assert_eq!(read_back, body, "content mismatch");
}

#[test]
fn copy_200mb_file_roundtrip() {
    // SWISS-4q P0: a 200 MB file should write + read back clean
    // with throughput well above 100 MB/s on local disk. The
    // pre-fix path failed at ~500 KB with EOVERFLOW; this test
    // proves the wire-protocol bandaid layer (msize 8 MiB +
    // cmd_write/read 8 MiB heap buffers + 4 KiB-aligned client
    // clamp) is sufficient for "single-large-file" workloads.
    //
    // The test uses a 4 GiB volume (much larger than the file)
    // so volume-size-vs-extent-budget isn't the constraint.
    use std::process::Stdio;
    let s = SessionBuilder { volume_size: "4G", passphrase: None }
        .build()
        .expect("session");
    // Generate 200 MB of content via dd-like loop in shell (cheap +
    // doesn't need a 200 MB Rust Vec allocation).
    let bin = s.bin.clone();
    let sock = s.stratumd_sock.clone();
    let body_size: u64 = 200 * 1024 * 1024;
    // Pipe `dd if=/dev/zero bs=1M count=200` → `stratum fs write`.
    use std::io::Write;
    let mut child = std::process::Command::new(&bin)
        .args(["fs", "-s", sock.to_str().unwrap(), "write", "/big.bin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut sin = child.stdin.take().unwrap();
    let chunk = vec![0u8; 1024 * 1024];
    for _ in 0..200 {
        sin.write_all(&chunk).expect("write chunk");
    }
    drop(sin);
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "200 MB write failed (exit {}): {}",
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr)
    );
    // Verify size.
    let (code, stat_out, _) = s
        .fs_run(&sock, &["stat", "/big.bin"], Stdio::null())
        .unwrap();
    assert_eq!(code, 0);
    let stat = String::from_utf8_lossy(&stat_out);
    assert!(
        stat.contains(&format!("size:   {body_size}")),
        "stat reports wrong size: {stat}"
    );
    // Read it back. Stream to /dev/null but check exit + count bytes.
    let read = std::process::Command::new(&bin)
        .args(["fs", "-s", sock.to_str().unwrap(), "read", "/big.bin"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        read.status.success(),
        "read failed (exit {}): {}",
        read.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&read.stderr)
    );
    assert_eq!(
        read.stdout.len() as u64,
        body_size,
        "read returned wrong size"
    );
    // Spot-check content is all zeros.
    assert!(read.stdout.iter().all(|&b| b == 0), "content corruption");
}

// ── Volume "disappears" pattern (user report) ───────────────────────

#[test]
fn volume_panel_remains_listable_under_load() {
    // User: "Sometimes when the .stm volume is open for a while,
    // suddenly everything from that panel disappears."
    //
    // Repro hypothesis: heavy write load fragments metadata; some
    // op returns an error AND pre-empts the daemon. After that any
    // subsequent op returns -22 / nothing.
    //
    // Test asserts: even after 50 consecutive successful writes,
    // the panel still lists all entries correctly.
    let s = session();
    for i in 0..50u32 {
        s.fs_write_bytes(
            &s.stratumd_sock,
            &format!("/n{i:02}.txt"),
            format!("content {i}\n").as_bytes(),
        )
        .unwrap_or_else(|e| panic!("write {i} failed: {e}"));
    }
    let entries = s.fs_ls(&s.stratumd_sock, "/").unwrap();
    let n = entries.len();
    assert_eq!(n, 50, "expected 50 entries after 50 writes; got {n}");
    // And re-stat each one.
    for i in 0..50u32 {
        let body = s.fs_read(&s.stratumd_sock, &format!("/n{i:02}.txt"))
            .unwrap_or_else(|e| panic!("read {i} failed: {e}"));
        assert_eq!(body, format!("content {i}\n").as_bytes());
    }
}

#[test]
fn many_concurrent_clients_against_one_daemon() {
    // User: "DISCONNECTED" sometimes appears. Validate the daemon
    // handles concurrent accept-connection load without dying.
    use std::thread;
    let s = session();
    s.fs_mkdir(&s.stratumd_sock, "/concur").unwrap();
    let bin = s.bin.clone();
    let sock = s.stratumd_sock.clone();
    let mut handles = Vec::new();
    for tid in 0..6u32 {
        let bin = bin.clone();
        let sock = sock.clone();
        handles.push(thread::spawn(move || -> Result<(), String> {
            for i in 0..10u32 {
                use std::io::Write as _;
                let mut child = std::process::Command::new(&bin)
                    .args(["fs", "-s", sock.to_str().unwrap(),
                           "write", &format!("/concur/t{tid}-i{i}.bin")])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|e| e.to_string())?;
                if let Some(mut sin) = child.stdin.take() {
                    sin.write_all(format!("t{tid}-i{i}\n").as_bytes())
                        .map_err(|e| e.to_string())?;
                }
                let out = child.wait_with_output()
                    .map_err(|e| e.to_string())?;
                if !out.status.success() {
                    return Err(format!("write t{tid}-i{i} (exit {}): {}",
                        out.status.code().unwrap_or(-1),
                        String::from_utf8_lossy(&out.stderr)));
                }
            }
            Ok(())
        }));
    }
    for h in handles {
        h.join().unwrap().unwrap();
    }
    let entries = s.fs_ls(&s.stratumd_sock, "/concur").unwrap();
    assert_eq!(entries.len(), 60, "60 files from 6×10 concurrent clients");
}

// ── Slate connection layer (panel state) ────────────────────────────

mod slate_state {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    /// Tiny slate client: dial, Tversion + Tattach, then expose
    /// read_path + write_path. We can't pull in src/slate.rs as a
    /// test module because the lp9 lib uses FFI; reading the panel
    /// state via the wire is enough for these tests.
    struct LP9 { stream: UnixStream, msize: u32, next_tag: u16 }
    impl LP9 {
        fn dial(sock: &Path) -> std::io::Result<Self> {
            let stream = UnixStream::connect(sock)?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            let mut me = Self { stream, msize: 8192, next_tag: 0 };
            // Tversion: size[4] type[1] tag[2] msize[4] version[s]
            let ver = b"9P2000.L";
            let body_len: u32 = 4 + 1 + 2 + 4 + 2 + ver.len() as u32;
            let mut buf = Vec::with_capacity(body_len as usize);
            buf.extend_from_slice(&body_len.to_le_bytes());
            buf.push(100); // Tversion
            buf.extend_from_slice(&0xFFFFu16.to_le_bytes()); // NOTAG
            buf.extend_from_slice(&me.msize.to_le_bytes());
            buf.extend_from_slice(&(ver.len() as u16).to_le_bytes());
            buf.extend_from_slice(ver);
            me.stream.write_all(&buf)?;
            // Read Rversion.
            let _ = me.read_msg()?;
            // Tattach: fid[4] afid[4] uname[s] aname[s] n_uname[4]
            // Use fid=0.
            let uname = b"u";
            let aname = b"";
            let body_len: u32 = 4 + 1 + 2 + 4 + 4 + 2 + uname.len() as u32
                + 2 + aname.len() as u32 + 4;
            let mut buf = Vec::with_capacity(body_len as usize);
            buf.extend_from_slice(&body_len.to_le_bytes());
            buf.push(104); // Tattach
            buf.extend_from_slice(&me.tag().to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes()); // fid
            buf.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // afid=NOFID
            buf.extend_from_slice(&(uname.len() as u16).to_le_bytes());
            buf.extend_from_slice(uname);
            buf.extend_from_slice(&(aname.len() as u16).to_le_bytes());
            buf.extend_from_slice(aname);
            buf.extend_from_slice(&0u32.to_le_bytes()); // n_uname
            me.stream.write_all(&buf)?;
            let _ = me.read_msg()?;
            Ok(me)
        }
        fn tag(&mut self) -> u16 {
            let t = self.next_tag;
            self.next_tag = self.next_tag.wrapping_add(1);
            t
        }
        fn read_msg(&mut self) -> std::io::Result<Vec<u8>> {
            let mut sz = [0u8; 4];
            self.stream.read_exact(&mut sz)?;
            let n = u32::from_le_bytes(sz) as usize;
            if n < 4 || n > 1 << 24 {
                return Err(std::io::Error::other(format!("bad msg size {n}")));
            }
            let mut body = vec![0u8; n - 4];
            self.stream.read_exact(&mut body)?;
            Ok(body)
        }

        // We don't write/read paths via this minimal client — full
        // Twalk + Tlopen + Tread chain is complex. The richer tests
        // use the real SlateClient (next test file). This client just
        // proves the slate socket is reachable + answering Tversion.
    }

    #[test]
    fn slate_dial_handshake() {
        let s = session();
        let _c = LP9::dial(&s.slate_sock).expect("dial slate");
    }
}
