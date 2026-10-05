//! Application error types.

use thiserror::Error;

/// Errors that can occur while running Riftop.
#[derive(Debug, Error)]
pub enum Error {
    #[error("pcap error: {0}")]
    Pcap(#[from] pcap::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("no suitable network interface found")]
    NoInterface,

    #[error("invalid interface '{0}'")]
    InvalidInterface(String),

    #[error("permission denied — Riftop needs root (or CAP_NET_RAW) to capture packets")]
    PermissionDenied,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
