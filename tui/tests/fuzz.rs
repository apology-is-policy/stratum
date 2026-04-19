//! Crash-injection fuzzer (SOTA #4, v1b).
//!
//! Generates seeded-random operation sequences against a live 9P server,
//! SIGKILLs the server at a random mid-sequence point, then remounts and
//! verifies: (a) `stratum check` passes, (b) `stratum scrub` passes,
//! (c) every file in the last-synced model is readable with expected
//! content via a fresh 9P session.
//!
//! Scope v1b (see roadmap): unencrypted volumes, files in root, writes
//! at arbitrary offsets (capped at 32 KiB), sync/snap_create/snap_delete.
//! Snap rollback deferred to v1c — its correctness requires model-level
//! snapshotting of file state, which the v1b model doesn't track.
//!
//! Env controls:
//!   FUZZ_ITERS=N      — number of iterations (default 3)
//!   FUZZ_OPS=N        — ops per iteration (default 20)
//!   FUZZ_SEED=0xHEX   — base seed; subsequent iterations add i (default: time-based)
//!
//! Failure mode: on any check/scrub failure, invariant mismatch, or 9P
//! error, the panic message includes the seed for reproduction.

#[path = "../src/p9.rs"]
mod p9;

use p9::P9Client;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// 9P mode bits (mirror the server constants).
const P9_OREAD: u8 = 0;
const P9_OWRITE: u8 = 1;
const P9_ORDWR: u8 = 2;

// --- binary discovery (same pattern as integration.rs) ---

fn find_bin(name: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let mut dir = exe.parent().unwrap().to_path_buf();
    for _ in 0..8 {
        for sub in ["", "build", "dist"] {
            let c = if sub.is_empty() { dir.join(name) } else { dir.join(sub).join(name) };
            if c.exists() { return c; }
        }
        if !dir.pop() { break; }
    }
    PathBuf::from(name)
}

fn stratum_bin() -> PathBuf { find_bin("stratum") }

// --- seeded xorshift64 ---
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self { Rng(if seed == 0 { 0x9E3779B97F4A7C15 } else { seed }) }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn range(&mut self, hi: usize) -> usize { (self.next() % hi as u64) as usize }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        for _ in 0..len { v.push((self.next() & 0xFF) as u8); }
        v
    }
}

// --- operation set ---
//
// Paths are "f0".."f7" — small pool so ops collide and exercise overwrite,
// unlink-while-open, re-create, etc.
#[derive(Debug, Clone)]
enum Op {
    CreateFile(usize),              // name_idx
    Write(usize, u32, Vec<u8>),     // name_idx, offset, bytes
    Unlink(usize),
    Sync,                           // triggered via a Clunk of a sync-dirty fid
    SnapCreate(String),
    SnapDelete,                     // delete oldest extant snap
}

const NAME_POOL: usize = 8;
fn name_of(i: usize) -> String { format!("f{}", i % NAME_POOL) }

fn gen_ops(seed: u64, n: usize) -> Vec<Op> {
    let mut rng = Rng::new(seed);
    let mut ops = Vec::with_capacity(n);
    let mut snap_counter = 0u32;
    for _ in 0..n {
        let kind = rng.range(100);
        let op = if kind < 20 {
            Op::CreateFile(rng.range(NAME_POOL))
        } else if kind < 60 {
            let name = rng.range(NAME_POOL);
            let off = (rng.range(4096) as u32) & !3;  // aligned
            let len = 1 + rng.range(8192);
            Op::Write(name, off, rng.bytes(len))
        } else if kind < 75 {
            Op::Unlink(rng.range(NAME_POOL))
        } else if kind < 90 {
            Op::Sync
        } else if kind < 97 {
            snap_counter += 1;
            Op::SnapCreate(format!("snap_{}", snap_counter))
        } else {
            Op::SnapDelete
        };
        ops.push(op);
    }
    ops
}

// --- model ---
//
// Tracks file content that SHOULD be durable after a crash, i.e. the state
// as of the last successful Sync. Ops after last sync are tentative —
// they may or may not survive — so we don't verify them strongly.
#[derive(Default, Clone)]
struct ModelState {
    files: HashMap<usize, Vec<u8>>,
}

struct Model {
    current: ModelState,
    last_sync: ModelState,  // durable baseline
    snap_ids: Vec<u64>,
}

impl Model {
    fn new() -> Self {
        Model { current: ModelState::default(), last_sync: ModelState::default(), snap_ids: vec![] }
    }
    fn on_sync_success(&mut self) {
        self.last_sync = self.current.clone();
    }
}

// --- server lifecycle ---
struct Server {
    child: Child,
    sock: PathBuf,
}

impl Server {
    fn start(vol: &Path) -> Server {
        let sock = vol.parent().unwrap().join(format!("s.{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let child = Command::new(stratum_bin())
            .arg("serve")
            .arg(vol)
            .arg("--listen")
            .arg(format!("unix:{}", sock.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("stratum serve failed to spawn");
        // poll for socket up to 5s (unencrypted, no KDF — usually <100ms)
        let start = Instant::now();
        while !sock.exists() {
            if start.elapsed() > Duration::from_secs(5) {
                panic!("server did not create socket within 5s");
            }
            sleep(Duration::from_millis(20));
        }
        Server { child, sock }
    }
    fn kill_sigkill(&mut self) {
        // SIGKILL — simulate power loss, not graceful shutdown.
        unsafe { libc::kill(self.child.id() as i32, libc::SIGKILL); }
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.sock);
    }
    fn kill_graceful(&mut self) {
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM); }
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.sock);
    }
}

// --- op execution ---
//
// Each op opens a fresh fid by walking from the root attach-fid, then
// does its work, clunks. Simple, robust against earlier fid corruption.
//
// Durability model: Stratum's 9P server (src/p9/p9.c::h_clunk) calls
// stm_fs_sync whenever a write-dirty fid is clunked, and h_remove +
// h_snap_* sync on every successful call. So EVERY op that returns
// success through a completed clunk is durable post-crash. The model
// reflects this by snapshotting last_sync after any op whose full
// success path (including clunk) completed.
fn execute(client: &mut P9Client, root_fid: u32, op: &Op, model: &mut Model) {
    match op {
        Op::CreateFile(idx) => {
            let nf = match client.walk(root_fid, &[]) {
                Ok(f) => f, Err(_) => return,
            };
            let cr = client.create(nf, &name_of(*idx), 0o644, P9_ORDWR);
            let cl = client.clunk(nf);
            if cr.is_ok() && cl.is_ok() {
                // NO on_sync_success: h_clunk only syncs when the fid had a
                // write (size_dirty). A created-but-never-written file is
                // dirty in the tree's buffered-insert set but not durable
                // until the next sync-triggering op (write, unlink, snap).
                // Reflect this by advancing the current-model pointer but
                // NOT the last_sync baseline.
                model.current.files.entry(*idx).or_default();
            }
        }
        Op::Write(idx, off, bytes) => {
            let name = name_of(*idx);
            let nf = match client.walk(root_fid, &[name.as_str()]) {
                Ok(f) => f, Err(_) => return,
            };
            if client.open(nf, P9_OWRITE).is_err() { let _ = client.clunk(nf); return; }
            let w = client.write_data(nf, *off as u64, bytes);
            let cl = client.clunk(nf);
            if let (Ok(n), Ok(())) = (w, cl) {
                if n as usize == bytes.len() {
                    let f = model.current.files.entry(*idx).or_default();
                    let end = *off as usize + bytes.len();
                    if f.len() < end { f.resize(end, 0); }
                    f[*off as usize..end].copy_from_slice(bytes);
                    model.on_sync_success();
                }
            }
        }
        Op::Unlink(idx) => {
            let nf = match client.walk(root_fid, &[name_of(*idx).as_str()]) {
                Ok(f) => f, Err(_) => return,
            };
            // Tremove implicitly frees the fid. h_remove syncs on success.
            if client.remove(nf).is_ok() {
                model.current.files.remove(idx);
                model.on_sync_success();
            }
        }
        Op::Sync => {
            // No standalone Tsync in 9P2000; simulate by creating+deleting
            // a throwaway snapshot, both of which sync.
            let name = format!("__sync_{}", SystemTime::now()
                .duration_since(UNIX_EPOCH).unwrap().as_nanos());
            if let Ok(id) = client.snap_create(&name) {
                let _ = client.snap_delete(id);
                model.on_sync_success();
            }
        }
        Op::SnapCreate(name) => {
            if let Ok(id) = client.snap_create(name) {
                model.snap_ids.push(id);
                model.on_sync_success();
            }
        }
        Op::SnapDelete => {
            if let Some(&id) = model.snap_ids.first() {
                if client.snap_delete(id).is_ok() {
                    model.snap_ids.remove(0);
                    model.on_sync_success();
                }
            }
        }
    }
}

// --- verification ---
//
// After crash + remount, every file in the last-synced model must exist
// at root with the matching content. No claim is made about files that
// were only touched after the last sync.
fn verify(client: &mut P9Client, root_fid: u32, baseline: &ModelState, seed: u64) {
    for (idx, expected) in &baseline.files {
        let name = name_of(*idx);
        let fid = client
            .walk(root_fid, &[name.as_str()])
            .unwrap_or_else(|e| panic!("seed=0x{:x}: file {} missing post-crash: {}", seed, name, e));
        client
            .open(fid, P9_OREAD)
            .unwrap_or_else(|e| panic!("seed=0x{:x}: open {} failed: {}", seed, name, e));
        let mut got = Vec::new();
        let mut off = 0u64;
        loop {
            let chunk = client
                .read(fid, off, 65536)
                .unwrap_or_else(|e| panic!("seed=0x{:x}: read {} failed: {}", seed, name, e));
            if chunk.is_empty() { break; }
            got.extend_from_slice(&chunk);
            off += chunk.len() as u64;
        }
        let _ = client.clunk(fid);
        if got.as_slice() != expected.as_slice() {
            panic!(
                "seed=0x{:x}: file {} content mismatch\n  expected ({} bytes): {:02x?}\n  got      ({} bytes): {:02x?}",
                seed, name, expected.len(), &expected[..expected.len().min(32)],
                got.len(), &got[..got.len().min(32)],
            );
        }
    }
}

fn run_check(vol: &Path, seed: u64, tool: &str) {
    let out = Command::new(stratum_bin())
        .arg(tool)
        .arg(vol)
        .output()
        .expect("failed to spawn tool");
    if !out.status.success() {
        panic!(
            "seed=0x{:x}: {} failed (exit={:?})\nstdout: {}\nstderr: {}",
            seed, tool, out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
}

// --- top level ---

fn run_iteration(seed: u64, n_ops: usize) {
    // Fresh dir + volume.
    let dir = PathBuf::from(format!("/tmp/stratum-fuzz-{}-{:x}", std::process::id(), seed));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let vol = dir.join("vol.stm");
    let out = Command::new(stratum_bin())
        .args(["mkfs", vol.to_str().unwrap(), "32M"])
        .output()
        .expect("mkfs spawn");
    assert!(
        out.status.success(),
        "seed=0x{:x}: mkfs failed: {}", seed, String::from_utf8_lossy(&out.stderr)
    );

    // Generate op sequence + pick crash point (index into the sequence).
    let ops = gen_ops(seed, n_ops);
    let mut rng = Rng::new(seed ^ 0xDEAD_BEEF);
    let crash_at = rng.range(ops.len());

    // Phase A: run ops up to crash_at under a live server.
    let mut model = Model::new();
    {
        let mut server = Server::start(&vol);
        let mut client = P9Client::connect_unix(&server.sock).expect("connect");
        let root = client.attach("fuzz", "").expect("attach");

        for (i, op) in ops.iter().enumerate() {
            if i == crash_at { break; }
            if std::env::var("FUZZ_TRACE").is_ok() {
                eprintln!("    [{}] {:?}", i, op);
            }
            execute(&mut client, root, op, &mut model);
        }
        if std::env::var("FUZZ_TRACE").is_ok() {
            eprintln!("    crash at op {}", crash_at);
            eprintln!("    last_sync.files: {:?}",
                model.last_sync.files.iter()
                    .map(|(i, v)| (i, v.len())).collect::<Vec<_>>());
        }
        // Intentional SIGKILL — no graceful shutdown. Simulates power loss.
        drop(client);  // closes the unix socket
        server.kill_sigkill();
    }

    // Phase B: remount via tools. Both must report clean.
    run_check(&vol, seed, "check");
    run_check(&vol, seed, "scrub");

    // Phase C: reopen via 9P and verify last-sync model content.
    {
        let mut server = Server::start(&vol);
        let mut client = P9Client::connect_unix(&server.sock).expect("connect B");
        let root = client.attach("fuzz", "").expect("attach B");
        verify(&mut client, root, &model.last_sync, seed);
        drop(client);
        server.kill_graceful();
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn fuzz_crash_injection() {
    let iters: usize = std::env::var("FUZZ_ITERS")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(3);
    let ops: usize = std::env::var("FUZZ_OPS")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(20);
    let base_seed: u64 = std::env::var("FUZZ_SEED")
        .ok().and_then(|s| {
            let s = s.strip_prefix("0x").unwrap_or(&s);
            u64::from_str_radix(s, 16).ok()
        })
        .unwrap_or_else(|| {
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
        });

    eprintln!(
        "fuzz: {} iterations × {} ops, base_seed=0x{:x}",
        iters, ops, base_seed
    );

    for i in 0..iters {
        let seed = base_seed.wrapping_add(i as u64);
        eprintln!("  iter {}: seed=0x{:x}", i, seed);
        run_iteration(seed, ops);
    }

    eprintln!("fuzz: all {} iterations passed", iters);
}
