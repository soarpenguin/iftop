use std::fs;
use std::path::Path;

use crate::config::mod_types::Config;
use crate::error::{Error, Result};

pub fn parse_file(path: &Path) -> Result<Config> {
    let text = fs::read_to_string(path)
        .map_err(|e| Error::Other(format!("config {}: {e}", path.display())))?;
    toml::from_str(&text).map_err(|e| Error::Other(format!("config {}: {e}", path.display())))
}
