//! File panel — one side of the dual-pane layout.
//! Supports both 9P (stratum) and host FS (direct std::fs) backends.

use crate::hostfs::HostFs;
use crate::p9::{P9Client, DMDIR, OREAD, ORDWR};
use anyhow::{anyhow, Result};
use std::path::Path;

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
    backend: Backend,
}

impl Panel {
    pub fn new(label: &str) -> Self {
        Self {
            label: label.to_string(),
            entries: Vec::new(),
            cursor: 0,
            scroll_offset: 0,
            backend: Backend::None,
        }
    }

    pub fn is_connected(&self) -> bool {
        !matches!(self.backend, Backend::None)
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
    }

    pub fn refresh(&mut self) -> Result<()> {
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
        match &mut self.backend {
            Backend::P9 { path, .. } => {
                if entry.name == ".." { path.pop(); }
                else { path.push(entry.name); }
            }
            Backend::Host(h) => h.enter(&entry.name),
            Backend::None => return Ok(()),
        }
        self.cursor = 0;
        self.refresh()
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

    pub fn delete_selected(&mut self) -> Result<()> {
        let entry = match self.selected() {
            Some(e) if e.name != ".." => e.clone(),
            _ => return Ok(()),
        };
        match &mut self.backend {
            Backend::P9 { client, root_fid, path } => {
                let mut fpath: Vec<&str> = path.iter().map(|s| s.as_str()).collect();
                fpath.push(&entry.name);
                let fid = client.walk(*root_fid, &fpath)?;
                client.remove(fid)?;
                self.refresh()
            }
            Backend::Host(h) => { h.delete(&entry.name)?; self.refresh() }
            Backend::None => Err(anyhow!("not connected")),
        }
    }
}
