//! SWISS-4r-10: shared harness for end-to-end stability tests.
//!
//! Each test spawns its own stratumd + slate + host-fs trio in a
//! freshly-minted tempdir and exercises CRUD scenarios through the
//! same paths the TUI hits: slate's /event + /panels writes for UI
//! state, `stratum fs` CLI subprocess for backend ops.
//!
//! Discovery: the `stratum` monolith binary is located via
//!   $STM_BIN  env var (cmake/ci sets this), or
//!   ../../target/release/stratum (default cargo build), or
//!   ../../target/debug/stratum (fallback)

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

pub fn locate_stratum_bin() -> PathBuf {
    if let Ok(p) = std::env::var("STM_BIN") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return pb.canonicalize().unwrap_or(pb);
        }
    }
    for rel in [
        "target/release/stratum",
        "../../target/release/stratum",
        "../../../target/release/stratum",
        "target/debug/stratum",
        "../../target/debug/stratum",
        "../../../target/debug/stratum",
    ] {
        let p = PathBuf::from(rel);
        if p.exists() {
            return p.canonicalize().unwrap_or(p);
        }
    }
    panic!(
        "stratum binary not found — set STM_BIN or build with `cargo build --release` \
         (cwd={})",
        std::env::current_dir().unwrap_or_default().display()
    );
}

/// Wait for a Unix socket to appear (or timeout).
pub fn wait_for_sock(p: &Path, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    while !p.exists() {
        if start.elapsed() > timeout {
            return Err(anyhow!("socket {} never appeared", p.display()));
        }
        std::thread::sleep(Duration::from_millis(15));
    }
    Ok(())
}

pub struct DaemonGuard {
    pub child: Option<Child>,
    pub label: &'static str,
    pub log_path: Option<PathBuf>,
}

impl DaemonGuard {
    pub fn kill(&mut self) {
        if let Some(c) = self.child.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.child = None;
    }
    pub fn dump_log(&self) -> String {
        match self.log_path.as_ref() {
            Some(p) => std::fs::read_to_string(p).unwrap_or_default(),
            None => String::new(),
        }
    }
}
impl Drop for DaemonGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

/// One full test session: tempdir + stratumd + slate + host-fs.
pub struct Session {
    pub _tmp: tempfile::TempDir,
    pub bin: PathBuf,
    pub root: PathBuf,
    pub host_root: PathBuf,
    pub stm_path: PathBuf,
    pub stm_keyfile: PathBuf,
    pub stratumd_sock: PathBuf,
    pub stratumd_ctl_sock: PathBuf,
    pub slate_sock: PathBuf,
    pub host_fs_sock: PathBuf,
    pub stratumd: DaemonGuard,
    pub slate: DaemonGuard,
    pub host_fs: DaemonGuard,
}

pub struct SessionBuilder {
    pub volume_size: &'static str,
    pub passphrase: Option<String>,
}
impl Default for SessionBuilder {
    fn default() -> Self {
        Self { volume_size: "64M", passphrase: None }
    }
}

impl SessionBuilder {
    pub fn build(self) -> Result<Session> {
        let bin = locate_stratum_bin();
        let test_id = NEXT_TEST_ID.fetch_add(1, Ordering::SeqCst);
        let tmp = tempfile::Builder::new()
            .prefix(&format!("swiss4r-{}-{}-", std::process::id(), test_id))
            .tempdir()
            .context("create tempdir")?;
        let root = tmp.path().to_path_buf();
        let host_root = root.join("host");
        std::fs::create_dir_all(&host_root)?;
        let stm_path = root.join("v.stm");
        let stm_keyfile = root.join("v.stm.key");
        let stratumd_sock = root.join("stratumd.sock");
        let stratumd_ctl_sock = root.join("stratumd-ctl.sock");
        let slate_sock = root.join("slate.sock");
        let host_fs_sock = root.join("host-fs.sock");

        // mkfs the volume.
        let mut mkfs = Command::new(&bin);
        mkfs.arg("mkfs")
            .arg(&stm_path)
            .arg("--size")
            .arg(self.volume_size)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if self.passphrase.is_some() {
            mkfs.arg("--passphrase-stdin").stdin(Stdio::piped());
        } else {
            mkfs.stdin(Stdio::null());
        }
        let mut child = mkfs.spawn().context("spawn mkfs")?;
        if let Some(pass) = self.passphrase.as_ref() {
            use std::io::Write as _;
            if let Some(mut sin) = child.stdin.take() {
                sin.write_all(pass.as_bytes())?;
                sin.write_all(b"\n")?;
                drop(sin);
            }
        }
        let out = child.wait_with_output()?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(anyhow!("mkfs failed (exit {}): {}",
                out.status.code().unwrap_or(-1), stderr));
        }

        // Spawn host-fs.
        let host_log = root.join("host-fs.log");
        let host_fs_child = Command::new(&bin)
            .args([
                "host-fs",
                host_root.to_str().unwrap(),
                "--listen",
                host_fs_sock.to_str().unwrap(),
                "--allow-unauth",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&host_log)?))
            .spawn()
            .context("spawn host-fs")?;
        let host_fs = DaemonGuard {
            child: Some(host_fs_child),
            label: "host-fs",
            log_path: Some(host_log),
        };
        wait_for_sock(&host_fs_sock, Duration::from_secs(5))
            .context("host-fs socket appear")?;

        // Spawn stratumd.
        let stratumd_log = root.join("stratumd.log");
        let mut stratumd_args: Vec<String> = vec![
            "serve".into(),
            stm_path.to_string_lossy().into_owned(),
            "--listen".into(),
            stratumd_sock.to_string_lossy().into_owned(),
            "--keyfile".into(),
            stm_keyfile.to_string_lossy().into_owned(),
            "--ctl-listen".into(),
            stratumd_ctl_sock.to_string_lossy().into_owned(),
        ];
        if self.passphrase.is_some() {
            stratumd_args.push("--passphrase-stdin".into());
        }
        let stdin_setup = if self.passphrase.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        };
        let mut stratumd_child = Command::new(&bin)
            .args(&stratumd_args)
            .stdin(stdin_setup)
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&stratumd_log)?))
            .spawn()
            .context("spawn stratumd")?;
        if let Some(pass) = self.passphrase.as_ref() {
            use std::io::Write as _;
            if let Some(mut sin) = stratumd_child.stdin.take() {
                sin.write_all(pass.as_bytes())?;
                sin.write_all(b"\n")?;
                drop(sin);
            }
        }
        let stratumd = DaemonGuard {
            child: Some(stratumd_child),
            label: "stratumd",
            log_path: Some(stratumd_log),
        };
        wait_for_sock(&stratumd_sock, Duration::from_secs(8))
            .context("stratumd socket appear")?;

        // Spawn slate.
        let slate_log = root.join("slate.log");
        let slate_child = Command::new(&bin)
            .args([
                "slate",
                "serve",
                "--listen",
                slate_sock.to_str().unwrap(),
                "--allow-unauth",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&slate_log)?))
            .spawn()
            .context("spawn slate")?;
        let slate = DaemonGuard {
            child: Some(slate_child),
            label: "slate",
            log_path: Some(slate_log),
        };
        wait_for_sock(&slate_sock, Duration::from_secs(5))
            .context("slate socket appear")?;

        Ok(Session {
            _tmp: tmp,
            bin,
            root,
            host_root,
            stm_path,
            stm_keyfile,
            stratumd_sock,
            stratumd_ctl_sock,
            slate_sock,
            host_fs_sock,
            stratumd,
            slate,
            host_fs,
        })
    }
}

impl Session {
    /// `stratum fs -s SOCK ARGS` with stdin/stdout configured. Returns
    /// (exit code, stdout, stderr).
    pub fn fs_run(
        &self,
        sock: &Path,
        args: &[&str],
        stdin: Stdio,
    ) -> Result<(i32, Vec<u8>, Vec<u8>)> {
        let sock_str = sock.to_str().unwrap();
        let mut full = vec!["fs", "-s", sock_str];
        full.extend_from_slice(args);
        let out = Command::new(&self.bin)
            .args(&full)
            .stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        Ok((out.status.code().unwrap_or(-1), out.stdout, out.stderr))
    }

    /// Convenience: stratum fs ls SOCK PATH → kind+name list.
    pub fn fs_ls(&self, sock: &Path, path: &str) -> Result<Vec<(char, String)>> {
        let (code, out, err) = self.fs_run(sock, &["ls", path], Stdio::null())?;
        if code != 0 {
            return Err(anyhow!(
                "stratum fs ls {} (exit {}): {}",
                path, code, String::from_utf8_lossy(&err).trim()
            ));
        }
        let s = String::from_utf8_lossy(&out);
        let mut v = Vec::new();
        for line in s.lines() {
            let mut it = line.splitn(2, ' ');
            let kind = it.next().and_then(|s| s.chars().next()).unwrap_or('?');
            let name = it.next().unwrap_or("").to_string();
            if name == "." || name == ".." || name.is_empty() { continue; }
            v.push((kind, name));
        }
        Ok(v)
    }

    /// Convenience: stratum fs stat SOCK PATH → succeed/fail.
    pub fn fs_stat(&self, sock: &Path, path: &str) -> bool {
        match self.fs_run(sock, &["stat", path], Stdio::null()) {
            Ok((0, _, _)) => true,
            _ => false,
        }
    }

    /// Read a small file's content via stratum fs.
    pub fn fs_read(&self, sock: &Path, path: &str) -> Result<Vec<u8>> {
        let (code, out, err) = self.fs_run(sock, &["read", path], Stdio::null())?;
        if code != 0 {
            return Err(anyhow!(
                "stratum fs read {} (exit {}): {}",
                path, code, String::from_utf8_lossy(&err).trim()
            ));
        }
        Ok(out)
    }

    /// Write file content via stratum fs (stdin pipe).
    pub fn fs_write_bytes(&self, sock: &Path, path: &str, body: &[u8]) -> Result<()> {
        use std::io::Write as _;
        let sock_str = sock.to_str().unwrap();
        let mut child = Command::new(&self.bin)
            .args(["fs", "-s", sock_str, "write", path])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut sin) = child.stdin.take() {
            sin.write_all(body)?;
        }
        let out = child.wait_with_output()?;
        if !out.status.success() {
            return Err(anyhow!(
                "stratum fs write {} (exit {}): {}",
                path,
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(())
    }

    /// Mkdir via stratum fs.
    pub fn fs_mkdir(&self, sock: &Path, path: &str) -> Result<()> {
        let (code, _out, err) = self.fs_run(sock, &["mkdir", path], Stdio::null())?;
        if code != 0 {
            return Err(anyhow!(
                "stratum fs mkdir {} (exit {}): {}",
                path, code, String::from_utf8_lossy(&err).trim()
            ));
        }
        Ok(())
    }

    /// Delete (rm) via stratum fs.
    pub fn fs_rm(&self, sock: &Path, path: &str) -> Result<()> {
        let (code, _out, err) = self.fs_run(sock, &["rm", path], Stdio::null())?;
        if code != 0 {
            return Err(anyhow!(
                "stratum fs rm {} (exit {}): {}",
                path, code, String::from_utf8_lossy(&err).trim()
            ));
        }
        Ok(())
    }

    /// Walk a host file tree and copy each path into stratum (mirrors
    /// the TUI's expand_dirs_in_items + per-item perform_copy_one
    /// flow). Returns (copied, skipped, failed, last_error).
    pub fn copy_host_tree_to_stm(
        &self,
        src_root: &Path,
        dst_p9_root: &str,
    ) -> (u32, u32, u32, Option<String>) {
        let mut copied = 0u32;
        let mut skipped = 0u32;
        let mut failed = 0u32;
        let mut last_err: Option<String> = None;

        // Always emit the dst root mkdir if it doesn't already exist
        // (caller may have pre-created).
        if dst_p9_root != "/" {
            if !self.fs_stat(&self.stratumd_sock, dst_p9_root) {
                match self.fs_mkdir(&self.stratumd_sock, dst_p9_root) {
                    Ok(()) => copied += 1,
                    Err(e) => { failed += 1; last_err = Some(e.to_string()); }
                }
            }
        }
        let mut stack = vec![(src_root.to_path_buf(), dst_p9_root.to_string())];
        while let Some((src_dir, dst_dir)) = stack.pop() {
            let entries = match std::fs::read_dir(&src_dir) {
                Ok(e) => e,
                Err(_) => { failed += 1; continue; }
            };
            for ent in entries.flatten() {
                let p = ent.path();
                let name = match p.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n.to_string(),
                    None => { skipped += 1; continue; }
                };
                let dst = if dst_dir == "/" {
                    format!("/{name}")
                } else {
                    format!("{dst_dir}/{name}")
                };
                if p.is_dir() {
                    if !self.fs_stat(&self.stratumd_sock, &dst) {
                        match self.fs_mkdir(&self.stratumd_sock, &dst) {
                            Ok(()) => copied += 1,
                            Err(e) => { failed += 1; last_err = Some(e.to_string()); }
                        }
                    }
                    stack.push((p, dst));
                } else if p.is_file() {
                    let body = match std::fs::read(&p) {
                        Ok(b) => b,
                        Err(e) => {
                            failed += 1;
                            last_err = Some(format!("read {}: {e}", p.display()));
                            continue;
                        }
                    };
                    match self.fs_write_bytes(&self.stratumd_sock, &dst, &body) {
                        Ok(()) => copied += 1,
                        Err(e) => { failed += 1; last_err = Some(e.to_string()); }
                    }
                } else {
                    skipped += 1;
                }
            }
        }
        (copied, skipped, failed, last_err)
    }
}
