//! Host filesystem access — direct std::fs, no 9P needed.

use crate::panel::Entry;
use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

pub struct HostFs {
    pub root: PathBuf,
    pub cwd: PathBuf,
}

impl HostFs {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            cwd: root.to_path_buf(),
        }
    }

    pub fn path_str(&self) -> String {
        self.cwd.display().to_string()
    }

    pub fn list(&self) -> Result<Vec<Entry>> {
        let mut entries = Vec::new();
        if self.cwd != self.root {
            entries.push(Entry {
                name: "..".into(),
                is_dir: true,
                size: 0,
                mtime: 0,
            });
        }
        for e in fs::read_dir(&self.cwd)? {
            let e = e?;
            let meta = e.metadata()?;
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            entries.push(Entry {
                name: e.file_name().to_string_lossy().into_owned(),
                is_dir: meta.is_dir(),
                size: meta.len(),
                mtime,
            });
        }
        entries[if self.cwd != self.root { 1 } else { 0 }..]
            .sort_by(|a, b| {
                b.is_dir.cmp(&a.is_dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            });
        Ok(entries)
    }

    pub fn enter(&mut self, name: &str) {
        if name == ".." {
            self.cwd.pop();
        } else {
            self.cwd.push(name);
        }
    }

    pub fn read_file(&self, name: &str) -> Result<Vec<u8>> {
        Ok(fs::read(self.cwd.join(name))?)
    }

    pub fn write_file(&self, name: &str, data: &[u8]) -> Result<()> {
        Ok(fs::write(self.cwd.join(name), data)?)
    }

    pub fn mkdir(&self, name: &str) -> Result<()> {
        Ok(fs::create_dir(self.cwd.join(name))?)
    }

    pub fn delete(&self, name: &str) -> Result<()> {
        let path = self.cwd.join(name);
        if path.is_dir() {
            fs::remove_dir_all(path)?;
        } else {
            fs::remove_file(path)?;
        }
        Ok(())
    }
}
