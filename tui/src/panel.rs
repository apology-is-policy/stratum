//! File panel — one side of the dual-pane layout.
//! Supports both 9P (stratum) and host FS (direct std::fs) backends.

use crate::hostfs::HostFs;
use crate::p9::{P9Client, SnapshotInfo, DMDIR, OREAD, ORDWR};
use anyhow::{anyhow, Result};
use std::path::Path;

pub enum WriteHandle {
    P9Fid(u32),
    HostFile(std::fs::File),
}

pub enum ReadHandle {
    P9Fid(u32),
    HostFile(std::fs::File),
}

#[derive(Clone)]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: u32,
}

enum Backend {
    None,
    P9 {
        client: P9Client,
        root_fid: u32,
        path: Vec<String>,
    },
    Host(HostFs),
}

pub struct Panel {
    pub label: String,
    pub entries: Vec<Entry>,
    pub cursor: usize,
    pub scroll_offset: usize,
    pub selected: std::collections::HashSet<usize>,
    backend: Backend,
    /// Per-path cursor memory: key is the path we were in, value is the
    /// name of the entry under the cursor at the time we descended. On
    /// returning via "..", we restore the cursor to that entry.
    cursor_memory: std::collections::HashMap<String, String>,
}

impl Panel {
    pub fn new(label: &str) -> Self {
        Self {
            label: label.to_string(),
            entries: Vec::new(),
            cursor: 0,
            scroll_offset: 0,
            selected: std::collections::HashSet::new(),
            backend: Backend::None,
            cursor_memory: std::collections::HashMap::new(),
        }
    }

    pub fn is_connected(&self) -> bool {
        !matches!(self.backend, Backend::None)
    }

    pub fn is_host(&self) -> bool {
        matches!(self.backend, Backend::Host(_))
    }

    pub fn selected_entry(&self) -> Option<&Entry> {
        self.entries.get(self.cursor)
    }

    pub fn path_str(&self) -> String {
        match &self.backend {
            Backend::None => String::new(),
            Backend::P9 { path, .. } => {
                if path.is_empty() { "/".into() }
                else { format!("/{}", path.join("/")) }
            }
            Backend::Host(h) => h.path_str(),
        }
    }

    pub fn connect_9p_unix(&mut self, socket: &str) -> Result<()> {
        let mut c = P9Client::connect_unix(Path::new(socket))?;
        let root = c.attach("user", "")?;
        self.backend = Backend::P9 { client: c, root_fid: root, path: Vec::new() };
        self.refresh()
    }

    pub fn connect_9p_tcp(&mut self, addr: &str) -> Result<()> {
        let mut c = P9Client::connect_tcp(addr)?;
        let root = c.attach("user", "")?;
        self.backend = Backend::P9 { client: c, root_fid: root, path: Vec::new() };
        self.refresh()
    }

    pub fn connect_host(&mut self, root: &Path) -> Result<()> {
        self.backend = Backend::Host(HostFs::new(root));
        self.refresh()
    }

    pub fn disconnect(&mut self) {
        self.backend = Backend::None;
        self.entries.clear();
        self.cursor = 0;
        // Cursor memory is per-volume; stale if we switch backends.
        self.cursor_memory.clear();
    }

    pub fn refresh(&mut self) -> Result<()> {
        self.selected.clear(); // indices become stale after refresh
        self.entries = match &mut self.backend {
            Backend::None => Vec::new(),
            Backend::P9 { client, root_fid, path } => {
                let names: Vec<&str> = path.iter().map(|s| s.as_str()).collect();
                let dir_fid = client.walk(*root_fid, &names)?;
                let stats = client.readdir(dir_fid)?;
                client.clunk(dir_fid)?;
                let mut entries = Vec::new();
                if !path.is_empty() {
                    entries.push(Entry { name: "..".into(), is_dir: true, size: 0, mtime: 0 });
                }
                for s in stats {
                    let is_dir = s.is_dir();
                    entries.push(Entry { name: s.name, is_dir, size: s.length, mtime: s.mtime });
                }
                // Sort: directories first, then alphabetical (case-insensitive)
                let start = if !path.is_empty() { 1 } else { 0 }; // skip ".."
                entries[start..].sort_by(|a, b| {
                    b.is_dir.cmp(&a.is_dir)
                        .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                });
                entries
            }
            Backend::Host(h) => h.list()?,
        };
        self.cursor = self.cursor.min(self.entries.len().saturating_sub(1));
        Ok(())
    }

    pub fn selected(&self) -> Option<&Entry> {
        self.entries.get(self.cursor)
    }

    pub fn move_up(&mut self) {
        if self.cursor > 0 { self.cursor -= 1; }
    }

    pub fn move_down(&mut self) {
        if self.cursor + 1 < self.entries.len() { self.cursor += 1; }
    }

    pub fn page_up(&mut self, page: usize) {
        self.cursor = self.cursor.saturating_sub(page);
    }

    pub fn page_down(&mut self, page: usize) {
        self.cursor = (self.cursor + page).min(self.entries.len().saturating_sub(1));
    }

    pub fn home(&mut self) { self.cursor = 0; }
    pub fn end(&mut self) { self.cursor = self.entries.len().saturating_sub(1); }

    pub fn enter(&mut self) -> Result<()> {
        let entry = match self.selected() {
            Some(e) => e.clone(),
            None => return Ok(()),
        };
        if !entry.is_dir { return Ok(()); }

        // Remember the name under the cursor in the current directory, so
        // when we navigate back via ".." we can land on the same entry.
        // For ascending (entry.name == ".."), we'll want the cursor to
        // land on the directory we're leaving.
        let current_path = self.path_str();
        let leaving_into_name = if entry.name == ".." {
            // Record the leaf of current path as the target for the parent
            Some(Self::leaf_name(&current_path))
        } else {
            self.cursor_memory.insert(current_path.clone(), entry.name.clone());
            None
        };

        match &mut self.backend {
            Backend::P9 { path, .. } => {
                if entry.name == ".." { path.pop(); }
                else { path.push(entry.name); }
            }
            Backend::Host(h) => h.enter(&entry.name),
            Backend::None => return Ok(()),
        }
        self.cursor = 0;
        self.refresh()?;

        // Restore cursor: on ascent, land on the directory we came from.
        // On descent, restore whatever the user had selected there previously.
        let target_name = leaving_into_name
            .or_else(|| self.cursor_memory.get(&self.path_str()).cloned());
        if let Some(name) = target_name {
            if let Some(idx) = self.entries.iter().position(|e| e.name == name) {
                self.cursor = idx;
            }
        }
        Ok(())
    }

    fn leaf_name(path: &str) -> String {
        // path examples: "/", "/foo", "/foo/bar", on host: "/home/user/..."
        path.rsplit('/').find(|s| !s.is_empty()).unwrap_or("").to_string()
    }

    pub fn read_file(&mut self, name: &str) -> Result<Vec<u8>> {
        match &mut self.backend {
            Backend::P9 { client, root_fid, path } => {
                let mut fpath: Vec<&str> = path.iter().map(|s| s.as_str()).collect();
                fpath.push(name);
                let fid = client.walk(*root_fid, &fpath)?;
                client.open(fid, OREAD)?;
                let mut data = Vec::new();
                let mut offset = 0u64;
                loop {
                    let chunk = client.read(fid, offset, 8192)?;
                    if chunk.is_empty() { break; }
                    offset += chunk.len() as u64;
                    data.extend_from_slice(&chunk);
                }
                client.clunk(fid)?;
                Ok(data)
            }
            Backend::Host(h) => h.read_file(name),
            Backend::None => Err(anyhow!("not connected")),
        }
    }

    pub fn write_file(&mut self, name: &str, data: &[u8]) -> Result<()> {
        match &mut self.backend {
            Backend::P9 { client, root_fid, path } => {
                // Remove existing file first (create fails if it exists)
                if let Ok(old_fid) = client.walk(*root_fid, &[name]) {
                    let _ = client.remove(old_fid);
                }
                let names: Vec<&str> = path.iter().map(|s| s.as_str()).collect();
                let dir_fid = client.walk(*root_fid, &names)?;
                client.create(dir_fid, name, 0o644, ORDWR)?;
                let mut offset = 0u64;
                for chunk in data.chunks(8192) {
                    client.write_data(dir_fid, offset, chunk)?;
                    offset += chunk.len() as u64;
                }
                client.clunk(dir_fid)?;
                Ok(())
            }
            Backend::Host(h) => h.write_file(name, data),
            Backend::None => Err(anyhow!("not connected")),
        }
    }

    pub fn mkdir(&mut self, name: &str) -> Result<()> {
        match &mut self.backend {
            Backend::P9 { client, root_fid, path } => {
                let names: Vec<&str> = path.iter().map(|s| s.as_str()).collect();
                let dir_fid = client.walk(*root_fid, &names)?;
                client.create(dir_fid, name, DMDIR | 0o755, OREAD)?;
                client.clunk(dir_fid)?;
                self.refresh()
            }
            Backend::Host(h) => { h.mkdir(name)?; self.refresh() }
            Backend::None => Err(anyhow!("not connected")),
        }
    }

    /// Create a directory at a relative path (creates parents as needed).
    pub fn mkdir_path(&mut self, rel: &str) -> Result<()> {
        let parts: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
        match &mut self.backend {
            Backend::P9 { client, root_fid, path } => {
                let base: Vec<&str> = path.iter().map(|s| s.as_str()).collect();
                // Create each component incrementally
                for i in 0..parts.len() {
                    let mut walk_path = base.clone();
                    walk_path.extend_from_slice(&parts[..=i]);
                    // Try walking to it — if it exists, skip
                    if let Ok(fid) = client.walk(*root_fid, &walk_path) {
                        client.clunk(fid)?;
                        continue;
                    }
                    // Doesn't exist — create it
                    let mut parent_path = base.clone();
                    parent_path.extend_from_slice(&parts[..i]);
                    let dir_fid = client.walk(*root_fid, &parent_path)?;
                    client.create(dir_fid, parts[i], DMDIR | 0o755, OREAD)?;
                    client.clunk(dir_fid)?;
                }
                Ok(())
            }
            Backend::Host(h) => {
                let full = h.cwd.join(rel);
                std::fs::create_dir_all(full)?;
                Ok(())
            }
            Backend::None => Err(anyhow!("not connected")),
        }
    }

    /// Recursively list all files under a directory (returns relative paths).
    pub fn list_recursive(&mut self, dir_name: &str) -> Result<Vec<(String, bool, u64)>> {
        let mut result = Vec::new();
        self.list_recursive_inner(dir_name, dir_name, &mut result)?;
        Ok(result)
    }

    fn list_recursive_inner(&mut self, base: &str, rel: &str,
                            out: &mut Vec<(String, bool, u64)>) -> Result<()> {
        // Add the directory itself
        out.push((rel.to_string(), true, 0));

        match &mut self.backend {
            Backend::P9 { client, root_fid, path } => {
                let mut fpath: Vec<&str> = path.iter().map(|s| s.as_str()).collect();
                for part in rel.split('/').filter(|s| !s.is_empty()) {
                    fpath.push(part);
                }
                let dir_fid = client.walk(*root_fid, &fpath)?;
                let stats = client.readdir(dir_fid)?;
                client.clunk(dir_fid)?;

                let entries: Vec<(String, bool, u64)> = stats.iter()
                    .map(|s| (s.name.clone(), s.is_dir(), s.length))
                    .collect();
                // Need to drop the borrow on self before recursing
                for (name, is_dir, size) in entries {
                    let child_rel = format!("{rel}/{name}");
                    if is_dir {
                        self.list_recursive_inner(base, &child_rel, out)?;
                    } else {
                        out.push((child_rel, false, size));
                    }
                }
            }
            Backend::Host(h) => {
                let dir_path = h.cwd.join(rel);
                if let Ok(rd) = std::fs::read_dir(&dir_path) {
                    let entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
                    for e in entries {
                        let meta = e.metadata()?;
                        let name = e.file_name().to_string_lossy().into_owned();
                        let child_rel = format!("{rel}/{name}");
                        if meta.is_dir() {
                            self.list_recursive_inner(base, &child_rel, out)?;
                        } else {
                            out.push((child_rel, false, meta.len()));
                        }
                    }
                }
            }
            Backend::None => {}
        }
        Ok(())
    }

    /// Open a persistent read handle — file is opened and stays open.
    /// Name can contain "/" for nested paths.
    pub fn begin_read(&mut self, name: &str) -> Result<(ReadHandle, u64)> {
        match &mut self.backend {
            Backend::P9 { client, root_fid, path } => {
                let mut fpath: Vec<&str> = path.iter().map(|s| s.as_str()).collect();
                for part in name.split('/').filter(|s| !s.is_empty()) {
                    fpath.push(part);
                }
                let fid = client.walk(*root_fid, &fpath)?;
                let stat = client.stat(fid)?;
                client.open(fid, OREAD)?;
                Ok((ReadHandle::P9Fid(fid), stat.length))
            }
            Backend::Host(h) => {
                use std::io::Read;
                let p = h.cwd.join(name);
                let meta = std::fs::metadata(&p)?;
                let f = std::fs::File::open(p)?;
                Ok((ReadHandle::HostFile(f), meta.len()))
            }
            Backend::None => Err(anyhow!("not connected")),
        }
    }

    /// Read a chunk from a persistent read handle.
    pub fn read_from_handle(&mut self, handle: &mut ReadHandle,
                            offset: u64, len: u32) -> Result<Vec<u8>> {
        match handle {
            ReadHandle::P9Fid(fid) => {
                let client = match &mut self.backend {
                    Backend::P9 { client, .. } => client,
                    _ => return Err(anyhow!("backend mismatch")),
                };
                client.read(*fid, offset, len)
            }
            ReadHandle::HostFile(f) => {
                use std::io::{Read, Seek, SeekFrom};
                f.seek(SeekFrom::Start(offset))?;
                let mut buf = vec![0u8; len as usize];
                let n = f.read(&mut buf)?;
                buf.truncate(n);
                Ok(buf)
            }
        }
    }

    /// Close a read handle.
    pub fn end_read(&mut self, handle: ReadHandle) -> Result<()> {
        match handle {
            ReadHandle::P9Fid(fid) => {
                if let Backend::P9 { client, .. } = &mut self.backend {
                    client.clunk(fid)?;
                }
                Ok(())
            }
            ReadHandle::HostFile(_) => Ok(()),
        }
    }

    /// Open a persistent write handle — file is created and stays open.
    /// Open a persistent write handle. Name can contain "/" for nested paths.
    pub fn begin_write(&mut self, name: &str) -> Result<WriteHandle> {
        match &mut self.backend {
            Backend::P9 { client, root_fid, path } => {
                // Remove existing file if present (walk now properly
                // rejects partial walks, so this won't hit a parent dir)
                let mut full: Vec<&str> = path.iter().map(|s| s.as_str()).collect();
                for part in name.split('/').filter(|s| !s.is_empty()) {
                    full.push(part);
                }
                if let Ok(old_fid) = client.walk(*root_fid, &full) {
                    let _ = client.remove(old_fid);
                }
                // Walk to parent directory, create file
                let parts: Vec<&str> = name.split('/').filter(|s| !s.is_empty()).collect();
                let file_name = parts.last().ok_or_else(|| anyhow!("empty filename"))?;
                let mut parent: Vec<&str> = path.iter().map(|s| s.as_str()).collect();
                parent.extend_from_slice(&parts[..parts.len() - 1]);
                let dir_fid = client.walk(*root_fid, &parent)?;
                client.create(dir_fid, file_name, 0o644, ORDWR)?;
                Ok(WriteHandle::P9Fid(dir_fid))
            }
            Backend::Host(h) => {
                let full = h.cwd.join(name);
                // Ensure parent directory exists
                if let Some(parent) = full.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let f = std::fs::File::create(&full)?;
                Ok(WriteHandle::HostFile(f))
            }
            Backend::None => Err(anyhow!("not connected")),
        }
    }

    /// Write through a persistent handle (no walk/open/clunk overhead).
    pub fn write_to_handle(&mut self, handle: &mut WriteHandle,
                           offset: u64, data: &[u8]) -> Result<()> {
        match handle {
            WriteHandle::P9Fid(fid) => {
                let client = match &mut self.backend {
                    Backend::P9 { client, .. } => client,
                    _ => return Err(anyhow!("backend mismatch")),
                };
                let mut off = offset;
                for chunk in data.chunks(1048576 - 24) {
                    client.write_data(*fid, off, chunk)?;
                    off += chunk.len() as u64;
                }
                Ok(())
            }
            WriteHandle::HostFile(f) => {
                use std::io::{Seek, SeekFrom, Write};
                f.seek(SeekFrom::Start(offset))?;
                f.write_all(data)?;
                Ok(())
            }
        }
    }

    /// Close a write handle.
    pub fn end_write(&mut self, handle: WriteHandle) -> Result<()> {
        match handle {
            WriteHandle::P9Fid(fid) => {
                if let Backend::P9 { client, .. } = &mut self.backend {
                    client.clunk(fid)?;
                }
                Ok(())
            }
            WriteHandle::HostFile(_f) => {
                // File is closed on drop
                Ok(())
            }
        }
    }

    /// Create an empty file (for chunked copy destination).
    pub fn create_empty_file(&mut self, name: &str) -> Result<()> {
        match &mut self.backend {
            Backend::P9 { client, root_fid, path } => {
                let names: Vec<&str> = path.iter().map(|s| s.as_str()).collect();
                let dir_fid = client.walk(*root_fid, &names)?;
                client.create(dir_fid, name, 0o644, ORDWR)?;
                client.clunk(dir_fid)?;
                Ok(())
            }
            Backend::Host(h) => {
                std::fs::File::create(h.cwd.join(name))?;
                Ok(())
            }
            Backend::None => Err(anyhow!("not connected")),
        }
    }

    /// Write a chunk at a specific offset (for chunked copy).
    pub fn write_chunk_at(&mut self, name: &str, offset: u64, data: &[u8]) -> Result<()> {
        match &mut self.backend {
            Backend::P9 { client, root_fid, path } => {
                let mut fpath: Vec<&str> = path.iter().map(|s| s.as_str()).collect();
                fpath.push(name);
                let fid = client.walk(*root_fid, &fpath)?;
                client.open(fid, ORDWR)?;
                let mut off = offset;
                for chunk in data.chunks(8192) {
                    client.write_data(fid, off, chunk)?;
                    off += chunk.len() as u64;
                }
                client.clunk(fid)?;
                Ok(())
            }
            Backend::Host(h) => {
                use std::io::{Seek, SeekFrom, Write};
                let path = h.cwd.join(name);
                let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
                f.seek(SeekFrom::Start(offset))?;
                f.write_all(data)?;
                Ok(())
            }
            Backend::None => Err(anyhow!("not connected")),
        }
    }

    pub fn delete_selected(&mut self) -> Result<()> {
        let entry = match self.selected_entry() {
            Some(e) if e.name != ".." => e.clone(),
            _ => return Ok(()),
        };
        self.delete_by_name(&entry.name)?;
        self.refresh()
    }

    pub fn delete_by_name(&mut self, name: &str) -> Result<()> {
        match &mut self.backend {
            Backend::P9 { client, root_fid, path } => {
                let mut fpath: Vec<&str> = path.iter().map(|s| s.as_str()).collect();
                fpath.push(name);
                let fid = client.walk(*root_fid, &fpath)?;
                client.remove(fid)?;
                Ok(())
            }
            Backend::Host(h) => h.delete(name),
            Backend::None => Err(anyhow!("not connected")),
        }
    }

    // ── snapshots (stratum only) ─────────────────────────────────────

    pub fn snap_create(&mut self, name: &str) -> Result<u64> {
        match &mut self.backend {
            Backend::P9 { client, .. } => client.snap_create(name),
            _ => Err(anyhow!("snapshots only supported on stratum")),
        }
    }

    pub fn snap_list(&mut self) -> Result<Vec<SnapshotInfo>> {
        match &mut self.backend {
            Backend::P9 { client, .. } => client.snap_list(),
            _ => Err(anyhow!("snapshots only supported on stratum")),
        }
    }

    pub fn snap_delete(&mut self, id: u64) -> Result<()> {
        match &mut self.backend {
            Backend::P9 { client, .. } => client.snap_delete(id),
            _ => Err(anyhow!("snapshots only supported on stratum")),
        }
    }

    pub fn snap_rollback(&mut self, id: u64) -> Result<()> {
        match &mut self.backend {
            Backend::P9 { client, .. } => client.snap_rollback(id),
            _ => Err(anyhow!("snapshots only supported on stratum")),
        }
    }
}
