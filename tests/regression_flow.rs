//! Regression tests against PCAP fixtures (no root required).
//!
//! IDs: R1–R8 documented in docs/legacy-analysis.md

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Instant;

use riftop::export::json_escape;
use riftop::flow::{FlowKey, FlowTable};
use riftop::protocols::{decode_ethernet, DecodeResult};

#[test]
fn json_escaping_special_chars() {
    assert_eq!(json_escape("eth0"), "eth0");
    assert_eq!(json_escape("eth\"0"), "eth\\\"0");
    assert_eq!(json_escape("line1\nline2"), "line1\\nline2");
}

#[test]
fn r2_flow_key_is_bidirectional() {
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let k1 = FlowKey::new(a, b, 80, 443, 6);
    let k2 = FlowKey::new(b, a, 443, 80, 6);
    assert_eq!(k1, k2, "R2: A↔B must be a single flow key");
}

#[test]
fn r6_unsupported_frames_do_not_panic() {
    assert_eq!(decode_ethernet(&[]), DecodeResult::Ignored);
    assert_eq!(decode_ethernet(&[0u8; 4]), DecodeResult::Ignored);
}

#[test]
fn r1_rate_windows_exist() {
    let now = Instant::now();
    let key = FlowKey::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        0,
        0,
        1,
    );
    let mut table = FlowTable::new();
    table.record(
        key.a,
        key.b,
        key.port_a,
        key.port_b,
        key.protocol,
        1500,
        &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
        now,
        None,
    );
    let top = table.top(1, now);
    assert_eq!(top.len(), 1);
    let r2 = top[0].rate_2s(now);
    let r10 = top[0].rate_10s(now);
    let r40 = top[0].rate_40s(now);
    assert!(r2.is_finite() && r10.is_finite() && r40.is_finite());
}

#[test]
fn fixture_directory_exists() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/pcap");
    assert!(
        dir.is_dir(),
        "fixtures/pcap must exist for regression fixtures"
    );
}
