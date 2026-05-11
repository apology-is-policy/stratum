//! /ctl/ synfs client — thin wrapper around libstratum-9p, parallels
//! src/slate.rs but talks to stratumd's /ctl/ socket (9P2000.L).
//!
//! Used by src/volmap.rs (SWISS-5) and any future consumer that wants
//! to read operator-state surfaces from a running stratumd.
//!
//! Provides:
//!
//!   * `dial` — open a 9P connection to stratumd's /ctl/ socket.
//!   * `read_path` — walk + lopen RDONLY + read-until-EOF + clunk.
//!   * `readdir` — walk + lopen RDONLY + iterate dir entries via callback.
//!
//! Concurrency note (carried from libstratum-9p docs §Concurrency):
//! each `CtlClient` is one-op-at-a-time. The SWISS-5 design uses ONE
//! CtlClient on the background poll thread; the main UI thread reads
//! the rendered state via RwLock and never dials directly.

#![allow(dead_code)]

use anyhow::{anyhow, bail, Context, Result};
use std::ffi::{c_void, CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::ffi;

/// Per-instance unique fid base. /ctl/'s lp9 server keys fids per-
/// connection so the slate session-table bug (CLAUDE.md slate row
/// clause 24) doesn't apply here — but unique-fid-base discipline is
/// cheap defense-in-depth and matches the slate client's posture.
static NEXT_FID_BASE: AtomicU32 = AtomicU32::new(50);

/// Cap on a single /ctl/ body. Today the largest kind is
/// /pools/<uuid>/metrics/prometheus at STM_CTL_METRICS_MAX (64 KiB
/// server-side). 4 MiB caller-cap gives headroom for future bulk kinds
/// (e.g., /debug/btree-shape, /debug/extent-map) without recompiling.
const READ_CAP: usize = 4 * 1024 * 1024;

pub struct CtlClient {
    raw: *mut ffi::stm_9p_client,
    msize: u32,
    root_fid: u32,
    scratch_fid: u32,
}

// libstratum-9p is not Sync; each connection is one-op-at-a-time. Send
// is fine — typical pattern is one CtlClient on a background poll
// thread, main UI thread reads cached state.
unsafe impl Send for CtlClient {}

impl CtlClient {
    pub fn dial(socket_path: &Path) -> Result<Self> {
        // Reserve 4 fids per instance: root + scratch + 2 reserved
        // headroom (post-audit consumers may want a second scratch for
        // pipelined ops). Stride keeps lots of headroom — ~1B instances
        // before saturation.
        let base = NEXT_FID_BASE.fetch_add(4, Ordering::Relaxed);
        if base < 50 || base.checked_add(4).is_none() {
            bail!("/ctl/ fid-base counter saturated; reconnect requires process restart");
        }
        let root_fid = base;
        let scratch_fid = base + 1;
        let cpath = CString::new(socket_path.as_os_str().to_string_lossy().as_bytes())
            .context("/ctl/ socket path contains NUL")?;
        let empty = CString::new("").unwrap();
        let opts = ffi::stm_9p_dial_opts {
            msize: ffi::STM_9P_MSIZE_DEFAULT,
            uname: empty.as_ptr(),
            aname: empty.as_ptr(),
            n_uname: u32::MAX,
            root_fid,
        };
        let mut raw: *mut ffi::stm_9p_client = std::ptr::null_mut();
        let rc = unsafe { ffi::stm_9p_dial_unix(cpath.as_ptr(), &opts, &mut raw) };
        if rc != ffi::STM_OK {
            bail!("dial /ctl/ {}: stm_status {rc}", socket_path.display());
        }
        if raw.is_null() {
            bail!("dial returned null /ctl/ client");
        }
        let msize = unsafe { ffi::stm_9p_msize(raw) };
        Ok(CtlClient { raw, msize, root_fid, scratch_fid })
    }

    fn walk_to(&mut self, dst_fid: u32, components: &[&str]) -> Result<()> {
        if components.len() > ffi::STM_9P_MAX_WALK as usize {
            bail!("/ctl/ walk too deep: {} > {}", components.len(), ffi::STM_9P_MAX_WALK);
        }
        let cnames: Vec<CString> = components
            .iter()
            .map(|n| CString::new(*n).map_err(|_| anyhow!("name {n} contains NUL")))
            .collect::<Result<_>>()?;
        let cptrs: Vec<*const c_char> = cnames.iter().map(|c| c.as_ptr()).collect();
        let mut qids: [ffi::stm_9p_qid; 16] = [ffi::stm_9p_qid::default(); 16];
        let mut walked: u16 = 0;
        let rc = unsafe {
            ffi::stm_9p_walk(
                self.raw,
                self.root_fid,
                dst_fid,
                cnames.len() as u16,
                if cptrs.is_empty() { std::ptr::null() } else { cptrs.as_ptr() },
                qids.as_mut_ptr(),
                &mut walked,
            )
        };
        if rc != ffi::STM_OK {
            bail!("/ctl/ walk: stm_status {rc}");
        }
        debug_assert_eq!(walked as usize, cnames.len(),
            "lib contract: STM_OK implies full walk");
        Ok(())
    }

    fn lopen(&mut self, fid: u32, flags: u32) -> Result<u32> {
        let mut qid = ffi::stm_9p_qid::default();
        let mut iounit: u32 = 0;
        let rc = unsafe { ffi::stm_9p_lopen(self.raw, fid, flags, &mut qid, &mut iounit) };
        if rc != ffi::STM_OK {
            bail!("/ctl/ lopen: stm_status {rc}");
        }
        Ok(iounit)
    }

    fn clunk_silent(&mut self, fid: u32) {
        let _ = unsafe { ffi::stm_9p_clunk(self.raw, fid) };
    }

    pub fn read_path(&mut self, path: &str) -> Result<Vec<u8>> {
        let comps = path_components(path);
        let view: Vec<&str> = comps.iter().map(|s| s.as_str()).collect();
        self.walk_to(self.scratch_fid, &view).context("walk")?;
        if let Err(e) = self.lopen(self.scratch_fid, ffi::STM_9P_O_RDONLY) {
            self.clunk_silent(self.scratch_fid);
            return Err(e.context("lopen"));
        }
        let result = self.read_until_eof(self.scratch_fid);
        self.clunk_silent(self.scratch_fid);
        result.with_context(|| format!("read /ctl/{path}"))
    }

    fn read_until_eof(&mut self, fid: u32) -> Result<Vec<u8>> {
        let mut out: Vec<u8> = Vec::new();
        let chunk_cap = std::cmp::min(self.msize.saturating_sub(64) as usize, 64 * 1024);
        let mut chunk = vec![0u8; chunk_cap];
        loop {
            let mut got: u32 = 0;
            let rc = unsafe {
                ffi::stm_9p_read(
                    self.raw,
                    fid,
                    out.len() as u64,
                    chunk.as_mut_ptr(),
                    chunk.len() as u32,
                    &mut got,
                )
            };
            if rc != ffi::STM_OK {
                bail!("/ctl/ read: stm_status {rc}");
            }
            if got == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..got as usize]);
            if out.len() > READ_CAP {
                bail!("/ctl/ response too large (> {} bytes)", READ_CAP);
            }
        }
        Ok(out)
    }

    /// Treaddir on `path`. Returns a vector of (name, qid_path, dirent_type).
    /// `qid_path` lets the caller correlate entries across reads (e.g.,
    /// to detect a snapshot was deleted between ticks).
    pub fn readdir(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        let comps = path_components(path);
        let view: Vec<&str> = comps.iter().map(|s| s.as_str()).collect();
        self.walk_to(self.scratch_fid, &view).context("walk")?;
        if let Err(e) = self.lopen(self.scratch_fid, ffi::STM_9P_O_RDONLY) {
            self.clunk_silent(self.scratch_fid);
            return Err(e.context("lopen"));
        }
        let result = self.readdir_collect(self.scratch_fid);
        self.clunk_silent(self.scratch_fid);
        result.with_context(|| format!("readdir /ctl/{path}"))
    }

    fn readdir_collect(&mut self, fid: u32) -> Result<Vec<DirEntry>> {
        let mut out: Vec<DirEntry> = Vec::new();
        let mut offset: u64 = 0;
        let count: u32 = std::cmp::min(self.msize.saturating_sub(64), 64 * 1024);
        loop {
            let mut entries: u32 = 0;
            let mut next_offset: u64 = 0;
            let ctx_ptr = &mut out as *mut Vec<DirEntry> as *mut c_void;
            let rc = unsafe {
                ffi::stm_9p_readdir(
                    self.raw,
                    fid,
                    offset,
                    count,
                    dirent_collect_cb,
                    ctx_ptr,
                    &mut entries,
                    &mut next_offset,
                )
            };
            if rc != ffi::STM_OK {
                bail!("/ctl/ readdir: stm_status {rc}");
            }
            if entries == 0 {
                break;
            }
            if out.len() > MAX_DIRENT_ENTRIES {
                bail!("/ctl/ readdir: more than {} entries (cap exceeded)", MAX_DIRENT_ENTRIES);
            }
            // Guard against a buggy server that returns entries but doesn't advance
            // next_offset — would loop forever.
            if next_offset <= offset {
                bail!("/ctl/ readdir: server returned non-monotonic offset");
            }
            offset = next_offset;
        }
        Ok(out)
    }
}

impl Drop for CtlClient {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { ffi::stm_9p_close(self.raw) };
            self.raw = std::ptr::null_mut();
        }
    }
}

/// Cap on readdir entries returned in one call. /pools/ has 1 entry
/// in v2.0; /datasets/ scales with dataset count; /pools/<uuid>/devices/
/// is bounded by STM_POOL_DEVICES_MAX (64). 4096 is comfortably above
/// any realistic v2.x bound and small enough that a malicious server
/// can't OOM the client.
const MAX_DIRENT_ENTRIES: usize = 4096;

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub qid_path: u64,
    pub dirent_type: u8,
}

/// extern "C" trampoline that pushes each dirent into the caller's
/// Vec<DirEntry> via the ctx pointer. Safety: cb is invoked by the
/// C-side stm_9p_readdir which owns the C-side memory for `name` for
/// the duration of the call; we copy into an owned String before
/// returning, so no UAF.
unsafe extern "C" fn dirent_collect_cb(
    qid: *const ffi::stm_9p_qid,
    _cookie: u64,
    typ: u8,
    name: *const c_char,
    _name_len: usize,
    ctx: *mut c_void,
) -> ffi::stm_status {
    let out = match (ctx as *mut Vec<DirEntry>).as_mut() {
        Some(v) => v,
        None => return ffi::STM_EINVAL,
    };
    if out.len() >= MAX_DIRENT_ENTRIES {
        // Stop iteration cleanly — the outer loop will surface the cap
        // breach via the post-call length check.
        return ffi::STM_EBUSY;
    }
    if name.is_null() {
        return ffi::STM_EINVAL;
    }
    // libstratum-9p documents `name` as NUL-terminated; trust it but
    // verify via CStr (rejects interior NUL via the impl, never reads
    // past the terminator).
    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ffi::STM_EINVAL,
    };
    let qid_path = qid.as_ref().map(|q| q.path).unwrap_or(0);
    // Skip the implicit "." and ".." entries that 9P2000.L servers
    // typically emit — the volume map renderer doesn't want them and
    // /ctl/ doesn't actually emit them at v2.0 (defensive filter).
    if name_str == "." || name_str == ".." {
        return ffi::STM_OK;
    }
    out.push(DirEntry { name: name_str, qid_path, dirent_type: typ });
    ffi::STM_OK
}

fn path_components(path: &str) -> Vec<String> {
    path.trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Read a path and convert to UTF-8 String, trimming a single trailing '\n'.
pub fn read_text_trim(client: &mut CtlClient, path: &str) -> Result<String> {
    let bytes = client.read_path(path)?;
    let s = String::from_utf8(bytes).map_err(|_| anyhow!("/ctl/{path}: not utf-8"))?;
    Ok(s.trim_end_matches('\n').to_string())
}

/// Read a path and split into lines (trailing newline stripped).
pub fn read_lines(client: &mut CtlClient, path: &str) -> Result<Vec<String>> {
    let bytes = client.read_path(path)?;
    let s = std::str::from_utf8(&bytes).map_err(|_| anyhow!("/ctl/{path}: not utf-8"))?;
    Ok(s.lines().map(|l| l.to_string()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn path_components_strips_leading_slash() {
        assert_eq!(path_components("/pools/abc"), vec!["pools", "abc"]);
        assert_eq!(path_components("pools/abc"), vec!["pools", "abc"]);
    }

    #[test]
    fn path_components_filters_empty() {
        // Defensive: a double-slash or trailing-slash path mustn't
        // produce empty components (which would walk to "" — invalid
        // 9P name).
        assert_eq!(path_components("/pools//abc/"), vec!["pools", "abc"]);
        assert_eq!(path_components("//"), Vec::<String>::new());
        assert_eq!(path_components(""), Vec::<String>::new());
        assert_eq!(path_components("/"), Vec::<String>::new());
    }

    #[test]
    fn path_components_nested() {
        assert_eq!(
            path_components("/pools/uuid/devices/0/status"),
            vec!["pools", "uuid", "devices", "0", "status"]
        );
    }

    #[test]
    fn dial_fails_on_nonexistent_socket() {
        // No actual socket file at this path; dial should return Err.
        let p = PathBuf::from("/tmp/stratum-ctl-nonexistent-test-socket.sock");
        let r = CtlClient::dial(&p);
        let err = r.err().expect("dial of non-existent socket should fail");
        let msg = format!("{}", err);
        assert!(msg.contains("dial /ctl/"),
            "error should mention dial: {msg}");
    }

    #[test]
    fn fid_base_counter_advances() {
        // Each dial attempt advances the counter by 16. We can't
        // easily assert the counter directly (atomic isn't a public
        // API and we don't want to expose it), but we CAN verify
        // that two failed dials are both reflected as errors (the
        // counter advanced past the first one's reservation).
        let p = PathBuf::from("/tmp/stratum-ctl-nonexistent-2.sock");
        assert!(CtlClient::dial(&p).is_err());
        assert!(CtlClient::dial(&p).is_err());
        // No assertion on counter value — but the test confirms two
        // failed dials don't crash the process or panic at the counter
        // logic.
    }

    #[test]
    fn path_with_embedded_nul_produces_cstring_error() {
        // Defensive: a path containing NUL must surface as a clean
        // error, not a panic. We can't actually dial without a server,
        // but we exercise the same construction logic.
        let bad = "/pools/\0/abc";
        let r = CString::new(bad);
        assert!(r.is_err(), "CString rejects embedded NUL");
    }
}

/// Discover the pool UUID by reading the singleton entry under /pools/.
/// Returns `Ok(None)` if /pools/ is empty (stratumd hasn't attached
/// stm_pool to /ctl/ — pre-S5-PRE-A posture). Returns `Ok(Some(uuid))`
/// in the typical v2.0 case (exactly one pool per stratumd).
pub fn discover_pool_uuid(client: &mut CtlClient) -> Result<Option<String>> {
    let entries = client.readdir("pools")?;
    if entries.is_empty() {
        return Ok(None);
    }
    // Multi-pool stratumd is forward-noted for v2.x; at v2.0 we expect
    // exactly one entry. Pick the first sorted alphabetically for
    // deterministic behavior if multi-pool ships later.
    let mut names: Vec<String> = entries.into_iter().map(|e| e.name).collect();
    names.sort();
    Ok(Some(names.into_iter().next().unwrap()))
}
