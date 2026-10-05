//! TOML configuration (optional file + CLI override).
//!
//! Search order:
//! 1. `--config PATH`
//! 2. `./riftop.toml`
//! 3. `$HOME/.config/riftop/config.toml`

pub mod cli;
pub mod file;
pub mod mod_types;

use std::path::{Path, PathBuf};

pub use file::parse_file;
pub use mod_types::Config;

use crate::error::{Error, Result};

impl Config {
    pub fn load(explicit: Option<&Path>) -> Result<Self> {
        if let Some(p) = explicit {
            if !p.exists() {
                return Err(Error::Other(format!(
                    "config file not found: {}",
                    p.display()
                )));
            }
            return parse_file(p);
        }
        match find_config_file() {
            Some(p) if p.exists() => parse_file(&p),
            _ => Ok(Self::default()),
        }
    }
}

fn find_config_file() -> Option<PathBuf> {
    let cwd_path = PathBuf::from("./riftop.toml");
    if cwd_path.exists() {
        return Some(cwd_path);
    }
    if let Ok(home) = std::env::var("HOME") {
        let p = PathBuf::from(home).join(".config/riftop/config.toml");
        if p.exists() {
            return Some(p);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sample() {
        let dir = std::env::temp_dir().join("riftop_cfg_test");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("t.toml");
        let _ = std::fs::write(
            &p,
            r#"
interface = "eth0"
filter = "tcp port 443"
ports = true
alert_rate_bps = 125000000
# comment
"#,
        );
        if let Ok(c) = parse_file(&p) {
            assert_eq!(c.interface.as_deref(), Some("eth0"));
            assert_eq!(c.filter.as_deref(), Some("tcp port 443"));
            assert!(c.ports);
            assert_eq!(c.alert_rate_bps, Some(125_000_000.0));
        } else {
            panic!("failed to parse sample config file");
        }
        let _ = std::fs::remove_file(&p);
    }
}
