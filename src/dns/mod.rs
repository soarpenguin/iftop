//! Reverse DNS lookup with a simple cache.

pub mod cache;
pub mod worker;

pub use cache::{DnsCache, DnsState};
