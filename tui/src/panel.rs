//! File panel — one side of the Norton Commander dual-pane layout.

use crate::p9::{P9Client, DMDIR, OREAD, ORDWR};
use anyhow::Result;

#[derive(Clone)]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: u32,
}

pub struct Panel {
    pub label: String,
    pub path: Vec<String>,     // current path components
    pub entries: Vec<Entry>,
    pub cursor: usize,
    pub scroll: usize,
    pub root_fid: u32,
    pub client: Option<P9Client>,
}

impl Panel {
    pub fn new(label: &str) -> Self {
        Self {
            label: label.to_string(),
            path: Vec::new(),
            entries: Vec::new(),
            cursor: 0,
            scroll: 0,
            root_fid: 0,
            client: None,
        }
    }

    pub fn connect_unix(&mut self, socket: &str) -> Result<()> {
        let mut c = P9Client::connect_unix(std::path::Path::new(socket))?;
        self.root_fid = c.attach("user", "")?;
        self.client = Some(c);
        self.path.clear();
        self.refresh()?;
        Ok(())
    }

    pub fn connect_tcp(&mut self, addr: &str) -> Result<()> {
        let mut c = P9Client::connect_tcp(addr)?;
        self.root_fid = c.attach("user", "")?;
        self.client = Some(c);
        self.path.clear();
        self.refresh()?;
        Ok(())
    }

    pub fn path_str(&self) -> String {
        if self.path.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", self.path.join("/"))
        }
    }

    pub fn refresh(&mut self) -> Result<()> {
        let c = match &mut self.client {
            Some(c) => c,
            None => return Ok(()),
        };

        // walk to current path from root
        let names: Vec<&str> = self.path.iter().map(|s| s.as_str()).collect();
        let dir_fid = c.walk(self.root_fid, &names)?;
        let stats = c.readdir(dir_fid)?;
        c.clunk(dir_fid)?;

        self.entries.clear();
        if !self.path.is_empty() {
            self.entries.push(Entry {
                name: "..".into(),
                is_dir: true,
                size: 0,
                mtime: 0,
            });
        }
        for s in stats {
            let is_dir = s.is_dir();
            self.entries.push(Entry {
                name: s.name,
                is_dir,
                size: s.length,
                mtime: s.mtime,
            });
        }
        self.cursor = self.cursor.min(self.entries.len().saturating_sub(1));
        Ok(())
    }

    pub fn selected(&self) -> Option<&Entry> {
        self.entries.get(self.cursor)
    }

    pub fn move_up(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    pub fn move_down(&mut self) {
        if self.cursor + 1 < self.entries.len() {
            self.cursor += 1;
        }
    }

    pub fn enter(&mut self) -> Result<()> {
        let entry = match self.entries.get(self.cursor) {
            Some(e) => e.clone(),
            None => return Ok(()),
        };
        if entry.name == ".." {
            self.path.pop();
            self.cursor = 0;
            return self.refresh();
        }
        if entry.is_dir {
            self.path.push(entry.name);
            self.cursor = 0;
            return self.refresh();
        }
        Ok(()) // regular file — no-op on enter for now
    }

    /// Read a file's contents (for copy operations).
    pub fn read_file(&mut self, name: &str) -> Result<Vec<u8>> {
        let c = self.client.as_mut().ok_or_else(|| anyhow::anyhow!("not connected"))?;
        let mut fpath: Vec<&str> = self.path.iter().map(|s| s.as_str()).collect();
        fpath.push(name);
        let fid = c.walk(self.root_fid, &fpath)?;
        c.open(fid, OREAD)?;
        let mut data = Vec::new();
        let mut offset = 0u64;
        loop {
            let chunk = c.read(fid, offset, 8192)?;
            if chunk.is_empty() {
                break;
            }
            offset += chunk.len() as u64;
            data.extend_from_slice(&chunk);
        }
        c.clunk(fid)?;
        Ok(data)
    }

    /// Write a file (for paste/copy operations).
    pub fn write_file(&mut self, name: &str, data: &[u8]) -> Result<()> {
        let c = self.client.as_mut().ok_or_else(|| anyhow::anyhow!("not connected"))?;
        let names: Vec<&str> = self.path.iter().map(|s| s.as_str()).collect();
        let dir_fid = c.walk(self.root_fid, &names)?;
        c.create(dir_fid, name, 0o644, ORDWR)?;
        let mut offset = 0u64;
        for chunk in data.chunks(8192) {
            c.write_data(dir_fid, offset, chunk)?;
            offset += chunk.len() as u64;
        }
        c.clunk(dir_fid)?;
        Ok(())
    }

    pub fn mkdir(&mut self, name: &str) -> Result<()> {
        let c = self.client.as_mut().ok_or_else(|| anyhow::anyhow!("not connected"))?;
        let names: Vec<&str> = self.path.iter().map(|s| s.as_str()).collect();
        let dir_fid = c.walk(self.root_fid, &names)?;
        c.create(dir_fid, name, DMDIR | 0o755, OREAD)?;
        c.clunk(dir_fid)?;
        self.refresh()
    }

    pub fn delete_selected(&mut self) -> Result<()> {
        let entry = match self.selected() {
            Some(e) => e.clone(),
            None => return Ok(()),
        };
        if entry.name == ".." {
            return Ok(());
        }
        let c = self.client.as_mut().ok_or_else(|| anyhow::anyhow!("not connected"))?;
        let mut fpath: Vec<&str> = self.path.iter().map(|s| s.as_str()).collect();
        fpath.push(&entry.name);
        let fid = c.walk(self.root_fid, &fpath)?;
        c.remove(fid)?;
        self.refresh()
    }
}
