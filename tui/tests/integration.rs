//! Integration tests — exercises the full stack via CLI (9P → server → filesystem).
//!
//! Each test spins up a fresh volume + server, runs operations, verifies results.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::fs;
use std::time::Instant;

/// Find a binary by walking up from the test exe to the project root.
fn find_bin(name: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let mut dir = exe.parent().unwrap().to_path_buf();
    for _ in 0..8 {
        // check dir/name, dir/build/name, dir/dist/name
        for sub in ["", "build", "dist"] {
            let candidate = if sub.is_empty() { dir.join(name) } else { dir.join(sub).join(name) };
            if candidate.exists() { return candidate; }
        }
        if !dir.pop() { break; }
    }
    PathBuf::from(name) // fallback: PATH
}

fn stratum_bin() -> PathBuf { find_bin("stratum") }
fn tui_bin() -> PathBuf { find_bin("stratum-tui") }

struct TestVolume {
    path: PathBuf,
    _tempdir: PathBuf,
}

impl TestVolume {
    fn new(name: &str, size: &str) -> Self {
        let dir = PathBuf::from(format!("/tmp/stratum-integ-{}-{}", name, std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let vol = dir.join("vol.stm");

        let out = Command::new(stratum_bin())
            .args(["mkfs", vol.to_str().unwrap(), size])
            .output()
            .expect("mkfs failed to start");
        assert!(out.status.success(), "mkfs failed: {}", String::from_utf8_lossy(&out.stderr));

        TestVolume { path: vol, _tempdir: dir }
    }

    fn cli(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(tui_bin());
        cmd.arg("cli").arg(self.path.to_str().unwrap());
        for a in args { cmd.arg(a); }
        cmd.output().expect("cli failed to start")
    }

    fn cli_ok(&self, args: &[&str]) -> String {
        let out = self.cli(args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(),
            "cli {:?} failed (exit={}):\nstdout: {}\nstderr: {}",
            args, out.status, stdout, stderr);
        stdout.into_owned()
    }

    fn cli_err(&self, args: &[&str]) -> String {
        let out = self.cli(args);
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    fn host_dir(&self) -> &Path {
        self.path.parent().unwrap()
    }
}

impl Drop for TestVolume {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self._tempdir);
    }
}

fn write_host_file(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, data).unwrap();
    p
}

fn read_host_file(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap()
}

// ── Tests ────────────────────────────────────────────────────────────

#[test]
fn test_small_file_roundtrip() {
    let vol = TestVolume::new("small-rt", "32M");
    let data = b"Hello, Stratum integration test!";
    let src = write_host_file(vol.host_dir(), "small.txt", data);

    // copy in
    vol.cli_ok(&["cp-in", src.to_str().unwrap(), "small.txt"]);

    // list — should show the file
    let ls = vol.cli_ok(&["ls"]);
    assert!(ls.contains("small.txt"), "ls output: {ls}");

    // copy out
    let dst = vol.host_dir().join("small_out.txt");
    vol.cli_ok(&["cp-out", "small.txt", dst.to_str().unwrap()]);

    // verify
    let got = read_host_file(&dst);
    assert_eq!(got, data);
}

#[test]
fn test_large_file_roundtrip() {
    let vol = TestVolume::new("large-rt", "32M");

    // 10MB of patterned data
    let size = 10 * 1024 * 1024;
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let src = write_host_file(vol.host_dir(), "big.bin", &data);

    vol.cli_ok(&["cp-in", src.to_str().unwrap(), "big.bin"]);

    let dst = vol.host_dir().join("big_out.bin");
    vol.cli_ok(&["cp-out", "big.bin", dst.to_str().unwrap()]);

    let got = read_host_file(&dst);
    assert_eq!(got.len(), data.len(), "size mismatch");
    assert_eq!(got, data, "data mismatch");
}

#[test]
fn test_autogrow_large_file() {
    // start with 4MB volume, copy 20MB file → volume must auto-grow
    let vol = TestVolume::new("autogrow", "4M");
    let size = 20 * 1024 * 1024;
    let data: Vec<u8> = (0..size).map(|i| ((i * 7 + 13) % 256) as u8).collect();
    let src = write_host_file(vol.host_dir(), "grow.bin", &data);

    vol.cli_ok(&["cp-in", src.to_str().unwrap(), "grow.bin"]);

    // verify volume grew
    let vol_size = fs::metadata(&vol.path).unwrap().len();
    assert!(vol_size > 4 * 1024 * 1024, "volume didn't grow: {vol_size}");

    // roundtrip verify
    let dst = vol.host_dir().join("grow_out.bin");
    vol.cli_ok(&["cp-out", "grow.bin", dst.to_str().unwrap()]);
    let got = read_host_file(&dst);
    assert_eq!(got, data);
}

#[test]
fn test_many_small_files() {
    let vol = TestVolume::new("many-small", "32M");

    // create 200 small files
    for i in 0..200 {
        let name = format!("file_{i:04}.txt");
        let data = format!("content of file {i}\n");
        let src = write_host_file(vol.host_dir(), &name, data.as_bytes());
        vol.cli_ok(&["cp-in", src.to_str().unwrap(), &name]);
    }

    // list — should show 200 files
    let ls = vol.cli_ok(&["ls"]);
    let count = ls.lines().filter(|l| l.contains("file_")).count();
    assert_eq!(count, 200, "expected 200 files, got {count}");

    // spot-check a few
    for i in [0, 99, 199] {
        let name = format!("file_{i:04}.txt");
        let dst = vol.host_dir().join(format!("out_{name}"));
        vol.cli_ok(&["cp-out", &name, dst.to_str().unwrap()]);
        let got = String::from_utf8(read_host_file(&dst)).unwrap();
        assert_eq!(got, format!("content of file {i}\n"));
    }
}

#[test]
fn test_mkdir_and_rm() {
    let vol = TestVolume::new("mkdir-rm", "16M");

    vol.cli_ok(&["mkdir", "docs"]);
    let ls = vol.cli_ok(&["ls"]);
    assert!(ls.contains("docs"), "mkdir failed: {ls}");

    vol.cli_ok(&["rm", "docs"]);
    let ls = vol.cli_ok(&["ls"]);
    assert!(!ls.contains("docs"), "rm failed: {ls}");
}

#[test]
fn test_delete_file() {
    let vol = TestVolume::new("del-file", "16M");
    let src = write_host_file(vol.host_dir(), "temp.txt", b"temporary");
    vol.cli_ok(&["cp-in", src.to_str().unwrap(), "temp.txt"]);

    let ls = vol.cli_ok(&["ls"]);
    assert!(ls.contains("temp.txt"));

    vol.cli_ok(&["rm", "temp.txt"]);
    let ls = vol.cli_ok(&["ls"]);
    assert!(!ls.contains("temp.txt"), "file still visible after rm: {ls}");
}

#[test]
fn test_overwrite_file() {
    let vol = TestVolume::new("overwrite", "16M");

    let src1 = write_host_file(vol.host_dir(), "data.txt", b"version 1");
    vol.cli_ok(&["cp-in", src1.to_str().unwrap(), "data.txt"]);

    let src2 = write_host_file(vol.host_dir(), "data_v2.txt", b"version 2 is longer");
    vol.cli_ok(&["cp-in", src2.to_str().unwrap(), "data.txt"]);

    let dst = vol.host_dir().join("data_out.txt");
    vol.cli_ok(&["cp-out", "data.txt", dst.to_str().unwrap()]);
    let got = String::from_utf8(read_host_file(&dst)).unwrap();
    assert_eq!(got, "version 2 is longer");
}

#[test]
fn test_empty_file() {
    let vol = TestVolume::new("empty", "16M");
    let src = write_host_file(vol.host_dir(), "empty.txt", b"");
    vol.cli_ok(&["cp-in", src.to_str().unwrap(), "empty.txt"]);

    let dst = vol.host_dir().join("empty_out.txt");
    vol.cli_ok(&["cp-out", "empty.txt", dst.to_str().unwrap()]);
    let got = read_host_file(&dst);
    assert!(got.is_empty(), "empty file roundtrip failed: {} bytes", got.len());
}

#[test]
fn test_binary_data_integrity() {
    let vol = TestVolume::new("binary", "16M");

    // all possible byte values
    let data: Vec<u8> = (0..=255u8).cycle().take(100_000).collect();
    let src = write_host_file(vol.host_dir(), "binary.dat", &data);
    vol.cli_ok(&["cp-in", src.to_str().unwrap(), "binary.dat"]);

    let dst = vol.host_dir().join("binary_out.dat");
    vol.cli_ok(&["cp-out", "binary.dat", dst.to_str().unwrap()]);
    let got = read_host_file(&dst);
    assert_eq!(got, data, "binary data integrity check failed");
}

#[test]
fn test_performance_scaling() {
    let vol = TestVolume::new("perf", "4M");

    // 1MB, 5MB, 10MB — verify roughly linear scaling
    let sizes = [1, 5, 10];
    let mut times = Vec::new();

    for mb in sizes {
        let size = mb * 1024 * 1024;
        let data: Vec<u8> = (0..size).map(|i| (i % 199) as u8).collect();
        let name = format!("perf_{mb}m.bin");
        let src = write_host_file(vol.host_dir(), &name, &data);

        let start = Instant::now();
        vol.cli_ok(&["cp-in", src.to_str().unwrap(), &name]);
        let elapsed = start.elapsed().as_secs_f64();
        times.push((mb, elapsed));
        eprintln!("  {mb}MB: {elapsed:.2}s ({:.0} MB/s)", mb as f64 / elapsed);
    }

    // 10MB should take less than 100x the time of 1MB (linear-ish)
    let ratio = times[2].1 / times[0].1;
    assert!(ratio < 50.0, "scaling is superlinear: {ratio:.1}x for 10x data");
}
