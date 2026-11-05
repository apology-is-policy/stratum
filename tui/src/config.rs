//! Simple INI-style config for volume history and preferences.
//!
//! File location: next to the binary, or ~/.config/stratum/config.ini
//! Format:
//!   [history]
//!   path=/path/to/volume1.stm
//!   path=/path/to/volume2.stm

use std::fs;
use std::path::PathBuf;

pub struct Config {
    pub history: Vec<String>,
    path: PathBuf,
}

impl Config {
    pub fn load() -> Self {
        let path = config_path();
        let mut history = Vec::new();
        if let Ok(content) = fs::read_to_string(&path) {
            for line in content.lines() {
                let line = line.trim();
                if let Some(val) = line.strip_prefix("path=") {
                    let val = val.trim();
                    if !val.is_empty() && !history.contains(&val.to_string()) {
                        history.push(val.to_string());
                    }
                }
            }
        }
        Config { history, path }
    }

    pub fn add_volume(&mut self, vol: &str) {
        self.history.retain(|h| h != vol);
        self.history.insert(0, vol.to_string());
        if self.history.len() > 20 {
            self.history.truncate(20);
        }
        self.save();
    }

    fn save(&self) {
        if let Some(dir) = self.path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let mut content = String::from("[history]\n");
        for h in &self.history {
            content.push_str(&format!("path={h}\n"));
        }
        let _ = fs::write(&self.path, content);
    }
}

fn config_path() -> PathBuf {
    if let Some(config_dir) = dirs::config_dir() {
        config_dir.join("stratum").join("config.ini")
    } else {
        PathBuf::from("stratum.ini")
    }
}
