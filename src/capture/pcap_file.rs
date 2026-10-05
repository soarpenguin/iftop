//! Offline PCAP reading for tests and regression (no privileges required).

use std::path::Path;

use pcap::{Capture, Offline};

use crate::error::{Error, Result};

/// Open a PCAP file for offline iteration.
pub fn open_pcap_file(path: impl AsRef<Path>) -> Result<Capture<Offline>> {
    let path = path.as_ref();
    Capture::from_file(path)
        .map_err(|e| Error::Other(format!("failed to open PCAP {}: {e}", path.display())))
}
