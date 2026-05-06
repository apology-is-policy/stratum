//! libstratum-9p FFI shim, dressed as v1's `P9Client` API.
//!
//! The v2 TUI wholesale-lifts v1's `panel.rs` / `app.rs` / `ui.rs`,
//! which call into a `P9Client` typed against the legacy 9P2000 wire.
//! This module preserves that API surface while delegating every op
//! through `libstratum-9p` (9P2000.L) — the chrome doesn't change, only
//! the wire underneath.
//!
//! Mapping highlights:
//!   - `Stat` struct keeps v1 fields (name, length, mtime, mode); the
//!     `mode` field synthesises DMDIR from the .L S_IFDIR bit so v1's
//!     `is_dir()` check still works.
//!   - `client.create(fid, name, perm, mode)`: routes to TLcreate
//!     (regular file) or TMkdir (DMDIR set), preserving v1's "fid
//!     rebinds to new file" semantics for files.
//!   - `client.remove(fid)`: v2 .L has no Tremove-by-fid. We track
//!     each fid's (parent_walk_path, name) at walk-time, then on
//!     remove() walk a fresh parent fid + Tunlinkat. Auto-detects
//!     directory via Tgetattr to set AT_REMOVEDIR.
//!   - `client.readdir(fid)`: per-entry Tgetattr to fill in size/mtime
//!     (v1 9P2000 returned full stats from one Tread; v2 .L splits
//!     these). Slow on big dirs; acceptable for panels < ~500 entries.
//!     Future: bulk-stat extension.
//!   - `client.snap_*`: stubbed — depend on /ctl/-on-stratumd (P9-CTL-2).
//!
//! Concurrency: each `P9Client` owns a `*mut stm_9p_client`, and
//! `libstratum-9p` is documented as NOT thread-safe across concurrent
//! calls. The raw pointer field naturally makes `P9Client` !Send /
//! !Sync, so consumers can't share it across threads.

#![allow(dead_code)]

use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::path::Path;

use crate::ffi;

// ── 9P2000 mode + perm bits the v1 chrome uses ───────────────────────

/// 9P2000 directory bit (top bit of the 32-bit mode word).
pub const DMDIR: u32 = 0x80000000;
/// 9P2000 Topen modes — values match Linux POSIX flag values for the
/// common cases, so the .L server accepts them as-is.
pub const OREAD:  u8 = 0;
pub const OWRITE: u8 = 1;
pub const ORDWR:  u8 = 2;

// ── Stat — v1 shape preserved; mode synthesises DMDIR ────────────────

#[derive(Clone)]
pub struct Stat {
    pub name:   String,
    pub length: u64,
    pub mtime:  u32,
    /// Synthesised v1 mode: low 12 bits = POSIX permissions; bit 31
    /// (DMDIR) set if the entry is a directory. v1 callers test
    /// `(stat.mode & DMDIR) != 0` — preserve that contract.
    pub mode:   u32,
}

impl Stat {
    pub fn is_dir(&self) -> bool { (self.mode & DMDIR) != 0 }
}

// ── Snapshot info (stubbed; data shape preserved) ────────────────────

#[derive(Clone, Debug)]
pub struct SnapshotInfo {
    pub id:   u64,
    pub gen:  u64,
    pub name: String,
}

// ── P9Client — owns the raw libstratum-9p handle + fid bookkeeping ──

pub struct P9Client {
    raw: *mut ffi::stm_9p_client,
    /// Caller-allocated fid for Tattach. v1 returned this from
    /// `attach()`; v2 lib takes it via dial_opts.root_fid.
    root_fid: u32,
    /// Monotonic fid counter for fresh allocations beyond root.
    next_fid: u32,
    /// For each fid we hand out via `walk()`, remember the path that
    /// produced it so `remove(fid)` can reconstruct (parent, name).
    /// Key: fid; Value: (start_fid, components_walked).
    walk_paths: HashMap<u32, (u32, Vec<String>)>,
}

impl P9Client {
    pub fn connect_unix(path: &Path) -> Result<Self> {
        let cpath = CString::new(path.as_os_str().to_string_lossy().as_bytes())
            .context("socket path contains NUL")?;
        let empty = CString::new("").unwrap();
        let opts = ffi::stm_9p_dial_opts {
            msize:    ffi::STM_9P_MSIZE_DEFAULT,
            uname:    empty.as_ptr(),
            aname:    empty.as_ptr(),
            n_uname:  u32::MAX,
            root_fid: 100,
        };
        let mut raw: *mut ffi::stm_9p_client = std::ptr::null_mut();
        let rc = unsafe { ffi::stm_9p_dial_unix(cpath.as_ptr(), &opts, &mut raw) };
        if rc != ffi::STM_OK {
            bail!("dial {}: stm_status {}", path.display(), rc);
        }
        if raw.is_null() { bail!("dial returned null client"); }
        Ok(P9Client {
            raw,
            root_fid: 100,
            next_fid: 101,
            walk_paths: HashMap::new(),
        })
    }

    /// TCP transport is not supported in v2 (stratumd is Unix-socket
    /// only). v1 callers that hit this branch should expect an error.
    pub fn connect_tcp(_addr: &str) -> Result<Self> {
        bail!("TCP transport not supported in v2 stratumd; use Unix socket")
    }

    /// v1 attach was a separate step; v2 dial does Tversion+Tattach
    /// in one shot. Return the root fid so v1 callers see the
    /// expected shape.
    pub fn attach(&mut self, _uname: &str, _aname: &str) -> Result<u32> {
        Ok(self.root_fid)
    }

    fn alloc_fid(&mut self) -> u32 {
        let f = self.next_fid;
        // Avoid overflow into NOFID (0xffffffff) — wrap to 101 and
        // hope no caller has a stale fid that high. Not perfect but
        // a long-running TUI session would have to walk billions of
        // times to hit this in practice.
        self.next_fid = match self.next_fid.checked_add(1) {
            Some(n) if n < ffi::STM_9P_NOFID => n,
            _ => 101,
        };
        f
    }

    pub fn walk(&mut self, start_fid: u32, names: &[&str]) -> Result<u32> {
        if names.len() > ffi::STM_9P_MAX_WALK as usize {
            bail!("path has {} components > {} max", names.len(), ffi::STM_9P_MAX_WALK);
        }
        // Prepare CStrings + ptr table.
        let cnames: Vec<CString> = names
            .iter()
            .map(|n| CString::new(*n).map_err(|_| anyhow!("name {n} contains NUL")))
            .collect::<Result<_>>()?;
        let cptrs: Vec<*const c_char> = cnames.iter().map(|c| c.as_ptr()).collect();

        let new_fid = self.alloc_fid();
        let mut qids: [ffi::stm_9p_qid; 16] = unsafe { std::mem::zeroed() };
        let mut walked: u16 = 0;
        let rc = unsafe {
            ffi::stm_9p_walk(
                self.raw,
                start_fid,
                new_fid,
                cnames.len() as u16,
                if cptrs.is_empty() { std::ptr::null() } else { cptrs.as_ptr() },
                qids.as_mut_ptr(),
                &mut walked,
            )
        };
        if rc != ffi::STM_OK {
            bail!("walk: stm_status {rc}");
        }
        // Record the path so `remove(new_fid)` can reconstruct it.
        let owned: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        self.walk_paths.insert(new_fid, (start_fid, owned));
        Ok(new_fid)
    }

    /// v1 Topen: mode is OREAD/OWRITE/ORDWR + flags. v2 .L Tlopen takes
    /// Linux flags directly; values for the common modes match. Pass
    /// through.
    pub fn open(&mut self, fid: u32, mode: u8) -> Result<()> {
        let mut qid: ffi::stm_9p_qid = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            ffi::stm_9p_lopen(self.raw, fid, mode as u32, &mut qid, std::ptr::null_mut())
        };
        if rc != ffi::STM_OK { bail!("lopen: stm_status {rc}"); }
        Ok(())
    }

    /// v1 Tcreate (file or dir under the dir-fid). DMDIR bit in `perm`
    /// routes to TMkdir; otherwise TLcreate. Both rebind fid for files
    /// (matching v1); for dirs v2 leaves the parent fid bound (callers
    /// don't care because they refresh via readdir).
    pub fn create(&mut self, fid: u32, name: &str, perm: u32, mode: u8) -> Result<()> {
        let cname = CString::new(name).context("name contains NUL")?;
        let mut qid: ffi::stm_9p_qid = unsafe { std::mem::zeroed() };
        if perm & DMDIR != 0 {
            let rc = unsafe {
                ffi::stm_9p_mkdir(
                    self.raw,
                    fid,
                    cname.as_ptr(),
                    perm & 0o7777,
                    0,
                    &mut qid,
                )
            };
            if rc != ffi::STM_OK { bail!("mkdir: stm_status {rc}"); }
            // Forget any walk-path bookkeeping for fid since the
            // parent is unchanged here, and the new dir is reachable
            // by name from fid's path. No-op.
        } else {
            let rc = unsafe {
                ffi::stm_9p_lcreate(
                    self.raw,
                    fid,
                    cname.as_ptr(),
                    mode as u32,
                    perm & 0o7777,
                    0,
                    &mut qid,
                    std::ptr::null_mut(),
                )
            };
            if rc != ffi::STM_OK { bail!("lcreate: stm_status {rc}"); }
            // fid rebinds to the new file. Update walk-path so a later
            // remove(fid) operates on the new entry.
            if let Some((start, mut comps)) = self.walk_paths.remove(&fid) {
                comps.push(name.to_string());
                self.walk_paths.insert(fid, (start, comps));
            }
        }
        Ok(())
    }

    pub fn read(&mut self, fid: u32, offset: u64, count: u32) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; count as usize];
        let mut got: u32 = 0;
        let rc = unsafe {
            ffi::stm_9p_read(self.raw, fid, offset, buf.as_mut_ptr(), count, &mut got)
        };
        if rc != ffi::STM_OK { bail!("read: stm_status {rc}"); }
        buf.truncate(got as usize);
        Ok(buf)
    }

    pub fn write_data(&mut self, fid: u32, offset: u64, data: &[u8]) -> Result<u32> {
        let mut written: u32 = 0;
        let rc = unsafe {
            ffi::stm_9p_write(
                self.raw,
                fid,
                offset,
                data.as_ptr(),
                data.len() as u32,
                &mut written,
            )
        };
        if rc != ffi::STM_OK { bail!("write: stm_status {rc}"); }
        Ok(written)
    }

    pub fn clunk(&mut self, fid: u32) -> Result<()> {
        let rc = unsafe { ffi::stm_9p_clunk(self.raw, fid) };
        // Forget walk-path bookkeeping regardless of rc — fid is gone
        // either way per 9P convention.
        self.walk_paths.remove(&fid);
        if rc != ffi::STM_OK { bail!("clunk: stm_status {rc}"); }
        Ok(())
    }

    /// v1 Tremove takes a fid and removes the entry it refers to. v2
    /// .L has only Tunlinkat(dir_fid, name, flags). We reconstruct
    /// (parent, name) from walk_paths, walk a fresh parent fid, and
    /// call Tunlinkat. Auto-detects directory via Tgetattr to set
    /// AT_REMOVEDIR.
    pub fn remove(&mut self, fid: u32) -> Result<()> {
        // Snapshot walk-path so we can release the borrow before
        // re-using `self`.
        let (start_fid, components) = self
            .walk_paths
            .get(&fid)
            .cloned()
            .ok_or_else(|| anyhow!("remove: fid {fid} has no recorded path"))?;
        if components.is_empty() {
            bail!("remove: cannot remove the root fid");
        }
        let name = components.last().unwrap().clone();
        let parent_components: Vec<&str> = components
            [..components.len() - 1]
            .iter()
            .map(|s| s.as_str())
            .collect();

        // Auto-detect directory via Tgetattr for AT_REMOVEDIR.
        let attr = self.getattr_raw(fid)?;
        let is_dir = (attr.mode & 0o170000) == 0o040000;

        // Walk a fresh parent fid (don't disturb the existing fid map
        // beyond what alloc_fid does).
        let parent_fid = self.walk(start_fid, &parent_components)?;
        let cname = CString::new(name.as_str()).context("name contains NUL")?;
        let flags: u32 = if is_dir { 0x200 } else { 0 }; // STM_9P_AT_REMOVEDIR
        let rc = unsafe { ffi::stm_9p_unlinkat(self.raw, parent_fid, cname.as_ptr(), flags) };
        // Always clunk parent. Original fid is also clunked since
        // unlinkat doesn't consume it.
        let _ = self.clunk(parent_fid);
        let _ = self.clunk(fid);
        if rc != ffi::STM_OK { bail!("unlinkat: stm_status {rc}"); }
        Ok(())
    }

    fn getattr_raw(&mut self, fid: u32) -> Result<ffi::stm_9p_attr> {
        let mut attr: ffi::stm_9p_attr = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            ffi::stm_9p_getattr(self.raw, fid, ffi::STM_9P_GETATTR_BASIC, &mut attr)
        };
        if rc != ffi::STM_OK { bail!("getattr: stm_status {rc}"); }
        Ok(attr)
    }

    /// Stat a fid. v1 Stat had `name` from the wire reply; v2's
    /// Tgetattr doesn't include the entry name, so we leave it empty.
    /// Callers that need the name should already have it from the
    /// readdir entry.
    pub fn stat(&mut self, fid: u32) -> Result<Stat> {
        let attr = self.getattr_raw(fid)?;
        let mut mode = attr.mode & 0o7777;
        if (attr.mode & 0o170000) == 0o040000 { mode |= DMDIR; }
        Ok(Stat {
            name: String::new(),
            length: attr.size,
            mtime: attr.mtime_sec as u32,
            mode,
        })
    }

    /// Readdir + per-entry Tgetattr to fill in size/mtime. Slower than
    /// v1 9P2000's bulk Tread on a dir — acceptable for panels with
    /// less than a few hundred entries. v1.1 forward-note: bulk-stat
    /// extension.
    ///
    /// v2 .L semantic-difference vs v1 9P2000: Treaddir requires the
    /// fid have its `is_open` flag set (server-side check; any
    /// successful Tlopen suffices, regardless of mode flags). v1
    /// callers don't open the dir-fid before readdir (lax 9P2000
    /// server), so the shim does it implicitly. Equivalent to v1's
    /// internal `self.open(fid, OREAD)` at the top of its readdir
    /// (see legacy tui/src/p9.rs:346).
    pub fn readdir(&mut self, fid: u32) -> Result<Vec<Stat>> {
        let mut qid_open: ffi::stm_9p_qid = unsafe { std::mem::zeroed() };
        let rc_open = unsafe {
            ffi::stm_9p_lopen(
                self.raw,
                fid,
                /*flags=*/OREAD as u32,
                &mut qid_open,
                std::ptr::null_mut(),
            )
        };
        if rc_open != ffi::STM_OK {
            bail!("readdir lopen: stm_status {rc_open}");
        }

        // Phase 1: collect names via stm_9p_readdir.
        let mut entries: Vec<DirentRaw> = Vec::new();
        extern "C" fn cb(
            _qid: *const ffi::stm_9p_qid,
            _cookie: u64,
            dt_type: u8,
            name: *const c_char,
            _name_len: usize,
            ctx: *mut c_void,
        ) -> ffi::stm_status {
            let entries: &mut Vec<DirentRaw> = unsafe { &mut *(ctx as *mut Vec<DirentRaw>) };
            let cname = unsafe { CStr::from_ptr(name) };
            entries.push(DirentRaw {
                name: cname.to_string_lossy().into_owned(),
                dt_type,
            });
            ffi::STM_OK
        }
        let mut offset: u64 = 0;
        for _ in 0..1024u32 {
            let mut emitted: u32 = 0;
            let mut next: u64 = 0;
            let prev = offset;
            let rc = unsafe {
                ffi::stm_9p_readdir(
                    self.raw,
                    fid,
                    offset,
                    0,
                    cb,
                    &mut entries as *mut _ as *mut c_void,
                    &mut emitted,
                    &mut next,
                )
            };
            if rc != ffi::STM_OK { bail!("readdir: stm_status {rc}"); }
            if emitted == 0 || next == prev { break; }
            offset = next;
        }
        // Filter "." and ".." — v1 didn't surface them through readdir
        // either; the panel's UI synthesises ".." for non-root paths.
        entries.retain(|e| e.name != "." && e.name != "..");

        // Phase 2: per-entry Tgetattr to fill size/mtime/mode.
        // We need the parent fid's walk-path to walk into each child.
        let (parent_start, parent_comps) = self
            .walk_paths
            .get(&fid)
            .cloned()
            .unwrap_or((self.root_fid, Vec::new()));
        let mut out: Vec<Stat> = Vec::with_capacity(entries.len());
        for e in entries {
            let mut comps: Vec<String> = parent_comps.clone();
            comps.push(e.name.clone());
            let walk_view: Vec<&str> = comps.iter().map(|s| s.as_str()).collect();
            // Best-effort: any walk failure (e.g. transient ENOENT)
            // surfaces a stat with zero size+mtime + a dir-bit guess
            // from dt_type. The panel still renders the entry name.
            let (length, mtime, mode) = match self.walk(parent_start, &walk_view) {
                Ok(efid) => {
                    let st = self.getattr_raw(efid).ok();
                    let _ = self.clunk(efid);
                    if let Some(a) = st {
                        let mut m = a.mode & 0o7777;
                        if (a.mode & 0o170000) == 0o040000 { m |= DMDIR; }
                        (a.size, a.mtime_sec as u32, m)
                    } else {
                        (0u64, 0u32, dt_type_to_v1_mode(e.dt_type))
                    }
                }
                Err(_) => (0u64, 0u32, dt_type_to_v1_mode(e.dt_type)),
            };
            out.push(Stat { name: e.name, length, mtime, mode });
        }
        Ok(out)
    }

    // ── Snapshot ops — stubbed pending P9-CTL-2 (/ctl/-on-stratumd) ─

    pub fn snap_create(&mut self, _name: &str) -> Result<u64> {
        bail!("snap_create: requires /ctl/-on-stratumd (P9-CTL-2 chunk)")
    }
    pub fn snap_list(&mut self) -> Result<Vec<SnapshotInfo>> {
        bail!("snap_list: requires /ctl/-on-stratumd (P9-CTL-2 chunk)")
    }
    pub fn snap_delete(&mut self, _id: u64) -> Result<()> {
        bail!("snap_delete: requires /ctl/-on-stratumd (P9-CTL-2 chunk)")
    }
    pub fn snap_rollback(&mut self, _id: u64) -> Result<()> {
        bail!("snap_rollback: requires /ctl/-on-stratumd (P9-CTL-2 chunk)")
    }
}

impl Drop for P9Client {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { ffi::stm_9p_close(self.raw) };
            self.raw = std::ptr::null_mut();
        }
    }
}

// ── helpers ──────────────────────────────────────────────────────────

struct DirentRaw {
    name: String,
    dt_type: u8,
}

fn dt_type_to_v1_mode(dt: u8) -> u32 {
    // POSIX DT_DIR=4, DT_REG=8, DT_LNK=10. Synth v1 mode bits.
    match dt {
        4  => DMDIR | 0o755,
        10 => 0o777,
        _  => 0o644,
    }
}
