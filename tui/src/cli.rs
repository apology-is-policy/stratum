//! Headless CLI mode — file operations without the TUI.
//!
//! Usage:
//!   stratum-tui cli <volume.stm> cp-in  <host-path> [stratum-dest-name]
//!   stratum-tui cli <volume.stm> cp-out <stratum-name> <host-path>
//!   stratum-tui cli <volume.stm> ls     [stratum-path]
//!   stratum-tui cli <volume.stm> mkdir  <stratum-path>
//!   stratum-tui cli <volume.stm> rm     <stratum-name>
//!   stratum-tui cli <volume.stm> snap   create <name>
//!   stratum-tui cli <volume.stm> snap   list

use crate::p9::{P9Client, DMDIR, OREAD, ORDWR};
use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server {
    child: Child,
    sock: String,
}

impl Server {
    fn start(volume: &str, stratum_bin: &str) -> Result<Self> {
        let sock = format!("/tmp/stratum-cli-{}.sock", std::process::id());
        let _ = std::fs::remove_file(&sock);
        let child = Command::new(stratum_bin)
            .arg("serve")
            .arg(volume)
            .arg("--listen")
            .arg(format!("unix:{sock}"))
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .context("cannot start stratum serve")?;

        // wait for socket
        let start = Instant::now();
        while !Path::new(&sock).exists() {
            if start.elapsed() > Duration::from_secs(5) {
                bail!("server did not create socket within 5s");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(Server { child, sock })
    }

}

impl Drop for Server {
    fn drop(&mut self) {
        // SIGTERM for graceful shutdown (server syncs before exit)
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM); }
        // Give the server up to 10s to sync and exit gracefully
        for _ in 0..100 {
            match self.child.try_wait() {
                Ok(Some(_)) => { let _ = std::fs::remove_file(&self.sock); return; }
                _ => std::thread::sleep(Duration::from_millis(100)),
            }
        }
        // Force kill if still alive
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.sock);
    }
}

fn find_stratum_bin() -> String {
    // same logic as app.rs
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let c = dir.join("stratum");
            if c.exists() { return c.display().to_string(); }
            let mut d = dir.to_path_buf();
            for _ in 0..5 {
                let t = d.join("build/stratum");
                if t.exists() { return t.display().to_string(); }
                if !d.pop() { break; }
            }
        }
    }
    let cwd = Path::new("build/stratum");
    if cwd.exists() { return cwd.display().to_string(); }
    "stratum".to_string()
}

pub fn run(args: &[String]) -> Result<()> {
    if args.len() < 2 {
        eprintln!("Usage: stratum-tui cli <volume.stm> <command> [args...]");
        eprintln!("Commands: cp-in, cp-out, ls, mkdir, rm, snap");
        std::process::exit(1);
    }

    let volume = &args[0];
    let cmd = &args[1];
    let rest = &args[2..];

    let bin = find_stratum_bin();
    eprintln!("[cli] using stratum binary: {bin}");
    eprintln!("[cli] starting server for {volume}...");
    let srv = Server::start(volume, &bin)?;
    let mut client = P9Client::connect_unix(Path::new(&srv.sock))?;
    let root_fid = client.attach("user", "")?;
    eprintln!("[cli] connected.");

    let result = match cmd.as_str() {
        "ls" => cmd_ls(&mut client, root_fid, rest),
        "mkdir" => cmd_mkdir(&mut client, root_fid, rest),
        "rm" => cmd_rm(&mut client, root_fid, rest),
        "cp-in" => cmd_cp_in(&mut client, root_fid, rest),
        "cp-out" => cmd_cp_out(&mut client, root_fid, rest),
        "snap" => cmd_snap(&mut client, root_fid, rest),
        _ => bail!("unknown command: {cmd}"),
    };

    // Drop client first (closes 9P connection), then wait for server to sync.
    // The server calls stm_fs_sync after the client disconnects.
    drop(client);
    // Now Server drops (SIGTERM) — sync is already done.

    result
}

fn cmd_ls(c: &mut P9Client, root: u32, args: &[String]) -> Result<()> {
    let path: Vec<&str> = if args.is_empty() {
        vec![]
    } else {
        args[0].split('/').filter(|s| !s.is_empty()).collect()
    };
    let fid = c.walk(root, &path)?;
    let entries = c.readdir(fid)?;
    c.clunk(fid)?;
    for e in &entries {
        let kind = if e.is_dir() { "d" } else { "-" };
        println!("{kind} {:>12}  {}", e.length, e.name);
    }
    println!("({} entries)", entries.len());
    Ok(())
}

fn cmd_mkdir(c: &mut P9Client, root: u32, args: &[String]) -> Result<()> {
    if args.is_empty() { bail!("mkdir requires a name"); }
    let fid = c.walk(root, &[])?;
    c.create(fid, &args[0], DMDIR | 0o755, OREAD)?;
    c.clunk(fid)?;
    println!("created directory: {}", args[0]);
    Ok(())
}

fn cmd_rm(c: &mut P9Client, root: u32, args: &[String]) -> Result<()> {
    if args.is_empty() { bail!("rm requires a name"); }
    let parts: Vec<&str> = args[0].split('/').filter(|s| !s.is_empty()).collect();
    let fid = c.walk(root, &parts)?;
    c.remove(fid)?;
    println!("removed: {}", args[0]);
    Ok(())
}

fn cmd_cp_in(c: &mut P9Client, root: u32, args: &[String]) -> Result<()> {
    if args.is_empty() { bail!("cp-in requires <host-path> [dest-name]"); }
    let host_path = &args[0];
    let dest_name = if args.len() > 1 {
        args[1].clone()
    } else {
        Path::new(host_path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".into())
    };

    eprintln!("[cli] reading {host_path}...");
    let data = std::fs::read(host_path).context("read host file")?;
    let total = data.len();
    eprintln!("[cli] {} bytes, writing to stratum:/{dest_name}...", total);

    // remove existing file if present, then create
    let dir_fid = c.walk(root, &[])?;
    if let Ok(old_fid) = c.walk(root, &[&dest_name]) {
        let _ = c.remove(old_fid);
    }
    c.create(dir_fid, &dest_name, 0o644, ORDWR)?;

    // write in chunks
    let chunk_size = 1048576 - 24;  // ~1MB, within 9P msize
    let mut offset = 0u64;
    let start = Instant::now();
    let mut last_report = Instant::now();

    for chunk in data.chunks(chunk_size) {
        c.write_data(dir_fid, offset, chunk)?;
        offset += chunk.len() as u64;

        if last_report.elapsed() > Duration::from_secs(1) {
            let pct = offset * 100 / total as u64;
            let elapsed = start.elapsed().as_secs_f64();
            let rate = offset as f64 / elapsed / 1024.0 / 1024.0;
            eprintln!("[cli] {offset}/{total} ({pct}%) {rate:.1} MB/s");
            last_report = Instant::now();
        }
    }

    c.clunk(dir_fid)?;

    let elapsed = start.elapsed().as_secs_f64();
    let rate = total as f64 / elapsed / 1024.0 / 1024.0;
    eprintln!("[cli] done: {total} bytes in {elapsed:.1}s ({rate:.1} MB/s)");
    Ok(())
}

fn cmd_cp_out(c: &mut P9Client, root: u32, args: &[String]) -> Result<()> {
    if args.len() < 2 { bail!("cp-out requires <stratum-name> <host-path>"); }
    let name = &args[0];
    let host_path = &args[1];

    let parts: Vec<&str> = name.split('/').filter(|s| !s.is_empty()).collect();
    let fid = c.walk(root, &parts)?;
    c.open(fid, OREAD)?;

    let mut data = Vec::new();
    let mut offset = 0u64;
    loop {
        let chunk = c.read(fid, offset, 1048576 - 24)?;
        if chunk.is_empty() { break; }
        offset += chunk.len() as u64;
        data.extend_from_slice(&chunk);
    }
    c.clunk(fid)?;

    std::fs::write(host_path, &data).context("write host file")?;
    eprintln!("[cli] wrote {} bytes to {host_path}", data.len());
    Ok(())
}

fn cmd_snap(_c: &mut P9Client, _root: u32, args: &[String]) -> Result<()> {
    // snapshots require the fs layer directly — for now just print help
    if args.is_empty() { bail!("snap requires: create <name> | list"); }
    eprintln!("snapshot operations via CLI require direct fs access (not yet via 9P)");
    eprintln!("use: stratum snap <volume> create|list|delete|rollback");
    Ok(())
}
