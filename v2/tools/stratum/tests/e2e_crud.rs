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
fn space_reclaim_across_write_rm_cycles() {
    // SWISS-4q P2 regression: pre-fix, unlink only mutated the
    // inode index — extent paddrs leaked. After one full-pool
    // write + rm cycle, the second write hit ENOSPC because the
    // allocator never saw the freed blocks. User-reported 2026-
    // 05-11: "copy 1.8 GB video to 3 GB stm volume, rm, repeat,
    // ENOSPC after one cycle".
    //
    // The fix: fs_unlink_inode_and_dirent now calls stm_sync_
    // truncate(ino, 0) before stm_inode_unlink to drop the
    // extents AND double-commits at the end so the allocator's
    // PENDING sweep predicate (`free_gen < committed_gen`)
    // reclaims the freed blocks before the next mutator.
    let s = session();
    let body = vec![0xCDu8; 30 * 1024 * 1024]; // 30 MB
    for cycle in 1u32..=5 {
        s.fs_write_bytes(&s.stratumd_sock, "/file", &body)
            .unwrap_or_else(|e| panic!("cycle {cycle} write: {e}"));
        s.fs_rm(&s.stratumd_sock, "/file")
            .unwrap_or_else(|e| panic!("cycle {cycle} rm: {e}"));
    }
    // Volume should still accept a fresh write after 5 cycles.
    s.fs_write_bytes(&s.stratumd_sock, "/final.bin", &body).unwrap();
    let read = s.fs_read(&s.stratumd_sock, "/final.bin").unwrap();
    assert_eq!(read.len(), body.len());
}

#[test]
fn rename_overwrite_reclaims_dst_extents() {
    // R128 P1-1 regression: rename's overwrite branch used to skip
    // the drop_ino + truncate + double-commit sequence that the
    // canonical unlink path performs. Pre-fix, every rename-overwrite
    // leaked the dst's extents (paddrs stayed PENDING for the session)
    // AND any dirty-buffer entry keyed at (ds, dst_ino) outlived its
    // inode → confused-deputy class bug.
    //
    // The fix: stm_fs_rename's overwrite branch now calls
    // fs_pre_inode_free_cleanup_locked + fs_post_inode_free_reclaim_locked
    // when dst is about to cascade-free (nlink==1 → unlink cascades).
    //
    // This test exercises path (b): the paddr-leak shape. Mirrors
    // space_reclaim_across_write_rm_cycles but uses rename-overwrite.
    // Without the fix, the first rename leaks ~30 MB of dst's blocks
    // permanently; after ~5 cycles the volume hits ENOSPC.
    let s = session();
    // Two concurrent files must fit (src + dst before rename) in the
    // default 64 MiB test volume. 20 MB each leaves headroom for
    // metadata + buffers. Per-cycle churn = 40 MB.
    let body_a = vec![0xCDu8; 20 * 1024 * 1024]; // 20 MB
    let body_b = vec![0xABu8; 20 * 1024 * 1024]; // 20 MB
    for cycle in 1u32..=5 {
        // Set up: write dst with body_a, write src with body_b.
        s.fs_write_bytes(&s.stratumd_sock, "/dst", &body_a)
            .unwrap_or_else(|e| panic!("cycle {cycle} dst write: {e}"));
        s.fs_write_bytes(&s.stratumd_sock, "/src", &body_b)
            .unwrap_or_else(|e| panic!("cycle {cycle} src write: {e}"));
        // Rename src → dst (overwrites dst). Pre-fix: dst's blocks
        // leak. Post-fix: dst's blocks reclaim via the double-commit.
        s.fs_run(&s.stratumd_sock, &["mv", "/src", "/dst"], Stdio::null())
            .unwrap_or_else(|e| panic!("cycle {cycle} mv: {e}"));
        // Clean up for next iteration.
        s.fs_rm(&s.stratumd_sock, "/dst")
            .unwrap_or_else(|e| panic!("cycle {cycle} cleanup rm: {e}"));
    }
    // Final write should succeed — total churn was 5 × 2 × 30 MB = 300 MB.
    s.fs_write_bytes(&s.stratumd_sock, "/final.bin", &body_a).unwrap();
    let read = s.fs_read(&s.stratumd_sock, "/final.bin").unwrap();
    assert_eq!(read.len(), body_a.len());
}

#[test]
fn write_unaligned_tail_4623_bytes() {
    // SWISS-4q P1 regression: real video files (and most real
    // workloads) have a logical size that isn't a multiple of
    // 4 KiB. Pre-fix, stm_sync_write_extent rejected the final
    // sub-block chunk with STM_EINVAL; user reported a 1.8 GB
    // video copy failing after the body had already streamed
    // through. fs_write_regular_locked now does read-modify-write
    // on the boundary block with a zeroed scratch.
    //
    // Smaller volume (8 MiB body + 4623 bytes) keeps the test fast.
    let s = session();
    let mut body = vec![0xACu8; 8 * 1024 * 1024];
    let tail: Vec<u8> = (0..4623u32).map(|i| (i & 0xff) as u8).collect();
    body.extend_from_slice(&tail);
    s.fs_write_bytes(&s.stratumd_sock, "/odd.bin", &body).unwrap();
    let read = s.fs_read(&s.stratumd_sock, "/odd.bin").unwrap();
    assert_eq!(read.len(), body.len(), "size mismatch");
    assert_eq!(read, body, "content mismatch on unaligned tail");
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

// ── Writeback amplification regression (user-reported small→2.8 GB) ──

#[test]
fn writeback_partial_drain_does_not_amplify_disk_usage() {
    // User-reported 2026-05-11 (post-c60b9e9 writeback activation):
    // copying a small file to a near-full volume cycled, blowing it
    // up to fill the entire 3 GB volume. Root cause: drain_ino on
    // partial cb failure left ALL ranges in the buffer; subsequent
    // commits re-emitted the already-written ranges as duplicate
    // extents, each iteration amplifying space usage.
    //
    // Repro shape:
    //   - 64 MB volume.
    //   - Write many sub-MiB files; most should succeed; eventually
    //     ENOSPC at the extent layer.
    //   - The number of successful files should be BOUNDED by the
    //     volume size / per-file size + reasonable metadata overhead,
    //     NOT magnified by the bug.
    //   - After rm-ing the successful files, fresh writes succeed
    //     again (allocator reclaims the dropped extents).
    let s = session();
    let body = vec![0xABu8; 512 * 1024]; // 512 KB per file (sub-1 MiB → buffered)
    let mut ok_names: Vec<String> = Vec::new();
    let mut last_err: Option<String> = None;
    // 64 MB / 512 KB = 128 files in the perfect case; bail at 200 to bound.
    for i in 0..200 {
        let name = format!("/f{:03}", i);
        match s.fs_write_bytes(&s.stratumd_sock, &name, &body) {
            Ok(_) => ok_names.push(name),
            Err(e) => {
                last_err = Some(e.to_string());
                break;
            }
        }
    }
    // Sanity: some writes succeeded.
    assert!(
        ok_names.len() > 0,
        "expected at least some writes to succeed before ENOSPC; last_err={last_err:?}"
    );
    // We should hit ENOSPC before exhausting our 200-file budget — the
    // 64 MB volume can't hold that much.
    assert!(
        ok_names.len() < 200,
        "expected to hit ENOSPC at some point within 200 small files"
    );
    // Pre-fix: with amplification, ok_names.len() could be tiny (each
    // "success" wrote N extents on disk). Post-fix: each ~512 KB write
    // → ~1 extent → ~128 writes fit. Allow 50% slack for metadata.
    assert!(
        ok_names.len() >= 60,
        "writeback amplification suspected: only {} writes succeeded \
         to a 64 MB volume (expected ≥ 60). \
         last_err={last_err:?}",
        ok_names.len()
    );
    // Recovery: rm everything we wrote, fresh write should succeed.
    for n in &ok_names {
        s.fs_rm(&s.stratumd_sock, n).unwrap_or_else(|e| {
            panic!("rm {n} after fill: {e}");
        });
    }
    s.fs_write_bytes(&s.stratumd_sock, "/recovery.bin", &body)
        .expect("post-rm fresh write should succeed");
    let read = s.fs_read(&s.stratumd_sock, "/recovery.bin").unwrap();
    assert_eq!(read.len(), body.len(), "recovery write size mismatch");
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

// ── S5-PRE-A: /ctl/ pool subtree visible after attach ────────────────

/// SWISS-5 S5-PRE-A regression: after stratumd attaches the fs's
/// pool + a sibling scrub to its /ctl/ instance, the readdir of
/// /pools/ MUST return exactly one entry (the volume's pool UUID)
/// and /pools/<uuid>/ MUST list scrub + metrics + devices.
///
/// Pre-S5-PRE-A, /pools/ readdir returned EMPTY because stratumd
/// never called stm_ctl_attach_pool. This test would fail with
/// `entries.is_empty()` against the prior binary.
#[test]
fn ctl_pool_subtree_visible_after_attach() {
    let s = session();
    let entries = s.fs_ls(&s.stratumd_ctl_sock, "/pools")
        .expect("readdir /pools");
    assert_eq!(entries.len(), 1,
        "S5-PRE-A: /pools/ MUST list exactly one pool (the attached one). \
         entries={:?}", entries);
    let (kind, uuid) = &entries[0];
    assert_eq!(*kind, 'd', "/pools/<uuid> must be a directory");
    assert_eq!(uuid.len(), 36,
        "pool UUID dirent should be 36-char canonical hex; got {:?}", uuid);

    // /pools/<uuid>/ now has scrub + metrics + devices entries.
    let pool_entries = s.fs_ls(&s.stratumd_ctl_sock, &format!("/pools/{uuid}"))
        .expect("readdir /pools/<uuid>");
    let names: Vec<&str> = pool_entries.iter().map(|(_, n)| n.as_str()).collect();
    assert!(names.contains(&"scrub"),
        "S5-PRE-A: /pools/<uuid>/scrub MUST appear post-attach_scrub. \
         entries={:?}", names);
    assert!(names.contains(&"metrics"),
        "/pools/<uuid>/metrics/ subtree MUST appear when pool attached");
    assert!(names.contains(&"devices"),
        "/pools/<uuid>/devices/ subtree MUST appear when pool attached");
}

/// SWISS-5 S5-PRE-C: /datasets/<id>/snapshots/ readdir lists every
/// snap for the dataset; per-snap leaf materializes id/name/txg/etc.
///
/// Spawn the session (root dataset = 1), create two snapshots via
/// /datasets/1/create-snapshot writes, then verify:
///   - /datasets/1/snapshots/ readdir returns exactly 2 entries
///   - each entry's name is decimal snap_id
///   - the leaf file's body contains the expected name and txg lines
#[test]
fn ctl_snapshots_subtree_lists_and_materializes() {
    let s = session();
    // Use stratum fs to drive /ctl/ writes. The session's stratumd
    // is launched with --ctl-listen so we can dial it for both
    // reads + writes. write-path writes "name\n" to create-snapshot
    // (per P9-CTL-1d-actions-snapshot-create's contract).
    //
    // Note: `stratum fs write` always Tfsyncs the ROOT_FID after
    // the write. /ctl/'s lp9 server returns STM_ENOTSUPPORTED for
    // fsync — this is correct (/ctl/ is a synthetic FS with no
    // backing storage to flush). The write itself completed
    // successfully BEFORE the fsync was attempted; the snapshot is
    // already created. We tolerate the non-zero exit + ENOTSUPPORTED
    // stderr below by NOT using fs_write_bytes (which fails the
    // call on non-zero exit). Direct Command::spawn handles it.
    use std::process::Command;
    let create = |name: &[u8]| {
        let mut child = Command::new(&s.bin)
            .args(["fs", "-s", s.stratumd_ctl_sock.to_str().unwrap(),
                   "write", "/datasets/1/create-snapshot"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn stratum fs write");
        use std::io::Write as _;
        if let Some(mut sin) = child.stdin.take() {
            sin.write_all(name).unwrap();
        }
        let out = child.wait_with_output().expect("wait");
        let stderr = String::from_utf8_lossy(&out.stderr);
        // Only acceptable failure is the post-op fsync ENOTSUPPORTED
        // ("status=-205"). Anything else is a real test failure.
        if !out.status.success() && !stderr.contains("status=-205") {
            panic!("create-snapshot failed (exit {:?}): {}",
                out.status.code(), stderr);
        }
    };
    create(b"alpha\n");
    create(b"beta\n");

    // Readdir the /datasets/1/snapshots/ subtree.
    let entries = s.fs_ls(&s.stratumd_ctl_sock, "/datasets/1/snapshots")
        .expect("readdir /datasets/1/snapshots");
    assert_eq!(entries.len(), 2,
        "S5-PRE-C: /datasets/1/snapshots/ MUST list both created snaps. \
         entries={:?}", entries);
    for (kind, name) in &entries {
        assert_eq!(*kind, '-', "snapshot info leaf must be a regular file");
        // Name must be all-digits (decimal snap_id).
        assert!(!name.is_empty(), "empty snap_id name");
        assert!(name.chars().all(|c| c.is_ascii_digit()),
            "snap dirent must be decimal snap_id, got {:?}", name);
    }

    // Materialize each leaf and verify the body contains both
    // "snapshot-id:" and "name:" lines.
    let mut seen_names: Vec<String> = Vec::new();
    for (_, sid) in &entries {
        let body = s.fs_read(
            &s.stratumd_ctl_sock,
            &format!("/datasets/1/snapshots/{}", sid),
        ).expect("read snapshot info");
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("snapshot-id: "),
            "leaf body MUST contain 'snapshot-id: '; got:\n{}", text);
        assert!(text.contains("dataset-id: 1\n"),
            "leaf body MUST contain 'dataset-id: 1'; got:\n{}", text);
        assert!(text.contains("name: "),
            "leaf body MUST contain 'name: '; got:\n{}", text);
        assert!(text.contains("hold-count: 0\n"),
            "fresh snap has hold-count 0; got:\n{}", text);
        // Extract name field for cross-validation.
        if let Some(name_line) = text.lines().find(|l| l.starts_with("name: ")) {
            seen_names.push(name_line[6..].to_string());
        }
    }
    assert_eq!(seen_names.len(), 2);
    seen_names.sort();
    assert_eq!(seen_names, vec!["alpha".to_string(), "beta".to_string()],
        "MUST see both snap names; got {:?}", seen_names);
}

/// SWISS-5 S5-PRE-C: snap_id must be a valid PRESENT snap belonging
/// to the queried dataset. Walking /datasets/<id>/snapshots/<bogus_id>
/// MUST return ENOENT (the walk-side guard binds dataset_id).
#[test]
fn ctl_snapshots_walk_refuses_unknown_id() {
    let s = session();
    // Don't create any snaps. Direct walk to a fabricated id.
    let r = s.fs_stat(&s.stratumd_ctl_sock,
        "/datasets/1/snapshots/9999999");
    assert!(!r, "walk to non-existent snap MUST fail");
}

/// SWISS-5 S5-PRE-A: the Prometheus exposition is the renderer's
/// primary data source. Verify it returns a non-empty body containing
/// the expected stratum_* gauge lines AFTER stratumd attaches pool +
/// scrub. Pre-S5-PRE-A this readdir would have failed with ENOENT
/// since /metrics/ lives under /pools/<uuid>/ which was invisible.
#[test]
fn ctl_metrics_prometheus_renders_after_attach() {
    let s = session();
    let entries = s.fs_ls(&s.stratumd_ctl_sock, "/pools")
        .expect("readdir /pools");
    assert_eq!(entries.len(), 1, "expected one pool");
    let uuid = &entries[0].1;
    let body = s.fs_read(
        &s.stratumd_ctl_sock,
        &format!("/pools/{uuid}/metrics/prometheus"),
    ).expect("read /pools/<uuid>/metrics/prometheus");
    let text = String::from_utf8_lossy(&body);
    // Sanity: non-empty + line-oriented ASCII + at least one stratum_*
    // gauge present. The specific gauges depend on attached subsystems
    // (S5-PRE-A attaches both fs + pool + scrub, so all three sections
    // should render).
    assert!(!body.is_empty(),
        "/pools/<uuid>/metrics/prometheus must render non-empty");
    assert!(text.contains("stratum_"),
        "S5-PRE-A: Prometheus body MUST contain stratum_* gauges; got:\n{}",
        text);
    // Specific gauges that S5-PRE-A unlocks via pool + scrub attach:
    // device gauges (was unavailable when pool was None) and scrub
    // gauges (was unavailable when scrub was None).
    assert!(text.contains("stratum_device") || text.contains("stratum_pool"),
        "S5-PRE-A: pool-attached metrics MUST surface device/pool gauges; got:\n{}",
        text);
}

/// SWISS-6 S6-TEST: snapshot lineage round-trip.
///
/// Create three snapshots in sequence + verify that the /ctl/ snapshot
/// info body carries a coherent lineage chain — each snap's prev-snap-id
/// is either 0 (root) or references a snap that exists in the listing.
/// Confirms the data layer surface that `snapgraph.rs::parse_snap_body`
/// + `lineage_depth` consume actually carries the information they need.
#[test]
fn ctl_snapshots_lineage_chain_coherent() {
    let s = session();
    use std::process::Command;
    let create = |name: &[u8]| {
        let mut child = Command::new(&s.bin)
            .args(["fs", "-s", s.stratumd_ctl_sock.to_str().unwrap(),
                   "write", "/datasets/1/create-snapshot"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn stratum fs write");
        use std::io::Write as _;
        if let Some(mut sin) = child.stdin.take() {
            sin.write_all(name).unwrap();
        }
        let out = child.wait_with_output().expect("wait");
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() && !stderr.contains("status=-205") {
            panic!("create-snapshot failed (exit {:?}): {}",
                out.status.code(), stderr);
        }
    };
    create(b"base\n");
    create(b"child-1\n");
    create(b"child-2\n");

    let entries = s.fs_ls(&s.stratumd_ctl_sock, "/datasets/1/snapshots")
        .expect("readdir /datasets/1/snapshots");
    assert_eq!(entries.len(), 3, "expected three snaps; got {:?}", entries);

    // Materialize each entry + parse the snapshot-id + prev-snap-id
    // fields. Build a (id, prev) map; assert each prev is either 0 or
    // references one of the ids we just saw.
    let mut by_id: std::collections::HashMap<u64, u64> = Default::default();
    let mut names: std::collections::HashMap<u64, String> = Default::default();
    for (_, sid_str) in &entries {
        let body = s.fs_read(
            &s.stratumd_ctl_sock,
            &format!("/datasets/1/snapshots/{}", sid_str),
        ).expect("read snapshot info");
        let text = String::from_utf8_lossy(&body);
        let mut snap_id: Option<u64> = None;
        let mut prev: Option<u64> = None;
        let mut name: Option<String> = None;
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("snapshot-id: ") {
                snap_id = v.parse().ok();
            } else if let Some(v) = line.strip_prefix("prev-snap-id: ") {
                prev = v.parse().ok();
            } else if let Some(v) = line.strip_prefix("name: ") {
                name = Some(v.to_string());
            }
        }
        let id = snap_id.expect("snapshot-id missing");
        let p = prev.expect("prev-snap-id missing");
        by_id.insert(id, p);
        names.insert(id, name.expect("name missing"));
    }
    assert_eq!(by_id.len(), 3);

    // Lineage coherence: each prev is either 0 or references a snap id
    // we observed in this listing. (The renderer's `lineage_depth`
    // treats missing-parent as "root", but the underlying surface MUST
    // carry consistent pointers within a single dataset's snap set.)
    let observed: std::collections::HashSet<u64> = by_id.keys().copied().collect();
    let mut root_count = 0;
    for (id, prev) in &by_id {
        if *prev == 0 {
            root_count += 1;
        } else {
            assert!(observed.contains(prev),
                "snap {} (name {:?}) carries prev-snap-id {} which is not in the dataset's snap set",
                id, names.get(id), prev);
            assert!(prev < id,
                "prev-snap-id {} must be < snapshot-id {} (allocator is monotonic per R29 P3-1)",
                prev, id);
        }
    }
    // At least one snap is a root (the first one created); typical
    // posture under stratum's default chain shape is exactly one root.
    assert!(root_count >= 1,
        "at least one snap MUST be a root (prev-snap-id 0); got root_count={}", root_count);
}
