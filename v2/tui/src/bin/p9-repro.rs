//! Reproducer for the "Read error: read: stm_status -22" bug.
//!
//! Mimics panel.rs::read_file's exact call sequence: walk + open
//! + read in a loop + clunk. Bypasses the TUI chrome so we can see
//! the shim's debug prints inline.
//!
//! Usage:
//!   cargo run --release --bin p9-repro -- <socket> <path>
//!
//! e.g. `cargo run --release --bin p9-repro -- /tmp/stm.sock /test.txt`.

#[path = "../ffi.rs"] mod ffi;
#[path = "../p9.rs"]  mod p9;

use std::path::Path;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: p9-repro <socket> <path>");
        std::process::exit(1);
    }
    let sock = &args[1];
    let path = &args[2];

    eprintln!("=== dial {sock} ===");
    let mut c = p9::P9Client::connect_unix(Path::new(sock))?;
    let root = c.attach("user", "")?;
    eprintln!("root_fid = {root}");

    // Mimic panel.rs::refresh — walk(root, []) → readdir → clunk.
    eprintln!("=== refresh (walk + readdir + clunk) ===");
    let dir_fid = c.walk(root, &[])?;
    let stats = c.readdir(dir_fid)?;
    eprintln!("readdir got {} entries: {:?}",
              stats.len(),
              stats.iter().map(|s| &s.name).collect::<Vec<_>>());
    c.clunk(dir_fid)?;

    // Mimic read_file (F3 view path) — walk + open + read loop + clunk.
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    eprintln!("=== read_file path components: {parts:?} ===");

    let fid = c.walk(root, &parts)?;
    eprintln!("walked fid = {fid}");

    c.open(fid, p9::OREAD)?;
    eprintln!("opened ok");

    let mut total = 0;
    let mut offset = 0u64;
    loop {
        let chunk = c.read(fid, offset, 8192)?;
        if chunk.is_empty() { break; }
        offset += chunk.len() as u64;
        total += chunk.len();
    }
    eprintln!("read total = {total}");

    c.clunk(fid)?;
    eprintln!("clunk ok — done");
    Ok(())
}
