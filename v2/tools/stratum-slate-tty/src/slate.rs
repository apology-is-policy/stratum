//! slate synfs client — thin wrapper around libstratum-9p.
//!
//! Provides the higher-level operations slate-tty needs:
//!
//!   * `dial` — open a 9P connection to a slate Unix socket.
//!   * `read_path` — walk + lopen RDONLY + read-until-EOF + clunk.
//!     Returns the raw body bytes.
//!   * `write_path` — walk + lopen WRONLY + chunked Twrite + clunk.
//!   * `redraw_once` — walk + lopen RDONLY + ONE Tread with the
//!     last-seen version as the offset; the slate daemon holds the
//!     read until version > offset (per SLATE-DESIGN §5), then
//!     returns the new version as a decimal string + '\n'.
//!
//! Concurrency note (carried from libstratum-9p docs): each
//! `SlateClient` is one-op-at-a-time. The slate-tty design uses TWO
//! `SlateClient` instances (one for the main thread, one for the
//! /redraw long-poll thread) precisely to avoid serialising
//! interactive ops behind a blocked redraw read.

use anyhow::{anyhow, bail, Context, Result};
use std::ffi::CString;
use std::os::raw::c_char;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::ffi;

/// Slate's per-instance session table is keyed by fid alone (see
/// v2/src/slate/slate.c::session_get_locked). When two concurrent
/// connections both use fid 101, slate's session_get_locked returns
/// the first match — usually the wrong session for the asking
/// connection. To dodge the collision, every `SlateClient` gets a
/// globally-unique fid base from this counter; root_fid = base,
/// scratch_fid = base + 1. The C-side socket tests dodge the same
/// issue by hand-picking 100/101 vs 200/201 (see test_slate_socket.c).
static NEXT_FID_BASE: AtomicU32 = AtomicU32::new(100);

/// Cap on a single slate body. The largest realistic surface today
/// is /panels/X/entries at ~64 KiB worst case (200 × 320). 4 MiB
/// gives /editor/content full headroom (1 MiB cap server-side).
const READ_CAP: usize = 4 * 1024 * 1024;

pub struct SlateClient {
    raw: *mut ffi::stm_9p_client,
    msize: u32,
    root_fid: u32,
    scratch_fid: u32,
}

// libstratum-9p is not Sync; each connection is one-op-at-a-time. Send
// is fine — we hand SlateClient between threads when constructing the
// /redraw worker but never use it concurrently.
unsafe impl Send for SlateClient {}

impl SlateClient {
    pub fn dial(socket_path: &Path) -> Result<Self> {
        // Reserve 16 fids per instance (root + scratch + 14 reserved
        // headroom for future per-op fids). Wraps to 100 on saturation
        // (with our 16-stride that means ~268 M instances before reuse).
        let base = NEXT_FID_BASE.fetch_add(16, Ordering::Relaxed);
        let root_fid = base;
        let scratch_fid = base + 1;
        let cpath = CString::new(socket_path.as_os_str().to_string_lossy().as_bytes())
            .context("socket path contains NUL")?;
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
            bail!("dial {}: stm_status {rc}", socket_path.display());
        }
        if raw.is_null() {
            bail!("dial returned null client");
        }
        let msize = unsafe { ffi::stm_9p_msize(raw) };
        Ok(SlateClient { raw, msize, root_fid, scratch_fid })
    }

    fn walk_to(&mut self, dst_fid: u32, components: &[&str]) -> Result<()> {
        if components.len() > ffi::STM_9P_MAX_WALK as usize {
            bail!("walk too deep: {} > {}", components.len(), ffi::STM_9P_MAX_WALK);
        }
        let cnames: Vec<CString> = components
            .iter()
            .map(|n| CString::new(*n).map_err(|_| anyhow!("name {n} contains NUL")))
            .collect::<Result<_>>()?;
        let cptrs: Vec<*const c_char> = cnames.iter().map(|c| c.as_ptr()).collect();
        let mut qids: [ffi::stm_9p_qid; 16] = unsafe { std::mem::zeroed() };
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
            bail!("walk: stm_status {rc}");
        }
        if (walked as usize) != cnames.len() {
            // Partial walk = not bound. clunk the dst (the lib didn't
            // bind it on partial walk; this is defensive).
            bail!("walk: partial — only {walked} of {} components found", cnames.len());
        }
        Ok(())
    }

    fn lopen(&mut self, fid: u32, flags: u32) -> Result<u32> {
        let mut qid = ffi::stm_9p_qid::default();
        let mut iounit: u32 = 0;
        let rc = unsafe { ffi::stm_9p_lopen(self.raw, fid, flags, &mut qid, &mut iounit) };
        if rc != ffi::STM_OK {
            bail!("lopen: stm_status {rc}");
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
        result.with_context(|| format!("read {path}"))
    }

    fn read_until_eof(&mut self, fid: u32) -> Result<Vec<u8>> {
        let mut out: Vec<u8> = Vec::new();
        let chunk_cap = std::cmp::min(self.msize.saturating_sub(64) as usize, 64 * 1024);
        let mut chunk = vec![0u8; chunk_cap];
        loop {
            if out.len() > READ_CAP {
                bail!("response too large (> {} bytes)", READ_CAP);
            }
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
                bail!("read: stm_status {rc}");
            }
            if got == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..got as usize]);
        }
        Ok(out)
    }

    pub fn write_path(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let comps = path_components(path);
        let view: Vec<&str> = comps.iter().map(|s| s.as_str()).collect();
        self.walk_to(self.scratch_fid, &view)?;
        let iounit = match self.lopen(self.scratch_fid, ffi::STM_9P_O_WRONLY) {
            Ok(io) => io,
            Err(e) => {
                self.clunk_silent(self.scratch_fid);
                return Err(e);
            }
        };
        let result = self.write_full(self.scratch_fid, data, iounit);
        self.clunk_silent(self.scratch_fid);
        result
    }

    fn write_full(&mut self, fid: u32, data: &[u8], iounit: u32) -> Result<()> {
        let chunk_cap: usize = if iounit == 0 {
            std::cmp::min(self.msize.saturating_sub(64) as usize, 64 * 1024)
        } else {
            std::cmp::min(iounit as usize, 64 * 1024)
        };
        let mut written: usize = 0;
        // Slate is offset-ignored on every writable kind (CLAUDE.md
        // slate row clause 19). We still pass `written` as the offset
        // for the standard 9P protocol — slate ignores it but the
        // wire format requires a value.
        while written < data.len() {
            let take = std::cmp::min(chunk_cap, data.len() - written);
            let mut got: u32 = 0;
            let rc = unsafe {
                ffi::stm_9p_write(
                    self.raw,
                    fid,
                    written as u64,
                    data[written..written + take].as_ptr(),
                    take as u32,
                    &mut got,
                )
            };
            if rc != ffi::STM_OK {
                bail!("write: stm_status {rc}");
            }
            if got == 0 {
                bail!("write: server returned 0 bytes");
            }
            written += got as usize;
        }
        Ok(())
    }

    /// Block on /redraw with `last_version` as the offset. Returns
    /// the new version when the slate daemon wakes us. A return of
    /// `Some(v)` means the version advanced to `v`. `None` means
    /// the daemon stopped (read returned 0 bytes pre-version-advance).
    pub fn redraw_once(&mut self, last_version: u64) -> Result<Option<u64>> {
        self.walk_to(self.scratch_fid, &["redraw"])?;
        if let Err(e) = self.lopen(self.scratch_fid, ffi::STM_9P_O_RDONLY) {
            self.clunk_silent(self.scratch_fid);
            return Err(e);
        }
        let mut buf = [0u8; 64];
        let mut got: u32 = 0;
        let rc = unsafe {
            ffi::stm_9p_read(
                self.raw,
                self.scratch_fid,
                last_version,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut got,
            )
        };
        self.clunk_silent(self.scratch_fid);
        if rc != ffi::STM_OK {
            bail!("redraw read: stm_status {rc}");
        }
        if got == 0 {
            return Ok(None);
        }
        let s = std::str::from_utf8(&buf[..got as usize])
            .map_err(|_| anyhow!("redraw response not utf-8"))?;
        let v: u64 = s.trim_end_matches('\n').parse()
            .map_err(|_| anyhow!("redraw response not a u64: {s:?}"))?;
        Ok(Some(v))
    }
}

impl Drop for SlateClient {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { ffi::stm_9p_close(self.raw) };
            self.raw = std::ptr::null_mut();
        }
    }
}

fn path_components(path: &str) -> Vec<String> {
    path.trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Read a path and convert to UTF-8 String, trimming a single trailing '\n'.
pub fn read_text_trim(client: &mut SlateClient, path: &str) -> Result<String> {
    let bytes = client.read_path(path)?;
    let s = String::from_utf8(bytes).map_err(|_| anyhow!("{path}: not utf-8"))?;
    Ok(s.trim_end_matches('\n').to_string())
}

/// Read a path and split on '\n' into lines (drops a single trailing empty line).
pub fn read_lines(client: &mut SlateClient, path: &str) -> Result<Vec<String>> {
    let bytes = client.read_path(path)?;
    let s = String::from_utf8(bytes).map_err(|_| anyhow!("{path}: not utf-8"))?;
    let mut lines: Vec<String> = s.split('\n').map(|s| s.to_string()).collect();
    if let Some(last) = lines.last() {
        if last.is_empty() {
            lines.pop();
        }
    }
    Ok(lines)
}
