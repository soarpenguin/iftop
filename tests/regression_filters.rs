//! Regression tests for network filters.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Instant;

use riftop::filters::{
    bpf_expression, is_link_local_v6, NetDirection, NetFilterV4, PacketFilter, ScreenFilter,
};
use riftop::flow::FlowTable;

#[test]
fn bpf_default_and_user() {
    assert_eq!(bpf_expression(None), "ip or ip6");
    assert_eq!(
        bpf_expression(Some("tcp port 22")),
        "(tcp port 22) and (ip or ip6)"
    );
}

#[test]
fn net_filter_v4_in_out_drop() {
    let f = NetFilterV4::parse("10.0.0.0/8").unwrap();
    assert_eq!(
        f.classify(Ipv4Addr::new(10, 1, 2, 3), Ipv4Addr::new(8, 8, 8, 8)),
        NetDirection::Out
    );
    assert_eq!(
        f.classify(Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(10, 9, 9, 9)),
        NetDirection::In
    );
    assert_eq!(
        f.classify(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)),
        NetDirection::Drop
    );
}

#[test]
fn packet_filter_counts_only_crossing_boundary() {
    let pf = PacketFilter::from_options(Some("10.0.0.0/24"), None, true).unwrap();
    let mut table = FlowTable::new();
    let now = Instant::now();
    let local = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    assert!(table.record_filtered(
        local,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        0,
        0,
        1,
        100,
        &[local],
        now,
        &pf,
        None,
    ));
    assert!(!table.record_filtered(
        local,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        0,
        0,
        1,
        50,
        &[local],
        now,
        &pf,
        None,
    ));
    assert_eq!(table.len(), 1);
    let s = table.top(1, now)[0];
    assert_eq!(s.sent_bytes, 100);
    assert_eq!(s.recv_bytes, 0);
}

#[test]
fn link_local_dropped_by_default() {
    let pf = PacketFilter::from_options(None, None, false).unwrap();
    let ll = IpAddr::V6(Ipv6Addr::from_str("fe80::abcd").unwrap());
    let g = IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap());
    assert!(pf.accept(ll, g).is_none());
}

#[test]
fn screen_filter_substring() {
    let sf = ScreenFilter::new(Some("cdn".into()));
    assert!(sf.matches("cdn.example.com", "10.0.0.1"));
    assert!(!sf.matches("api.example.com", "10.0.0.1"));
}

#[test]
fn is_link_local_helper() {
    assert!(is_link_local_v6(Ipv6Addr::from_str("fe80::1").unwrap()));
    assert!(!is_link_local_v6(
        Ipv6Addr::from_str("2001:db8::1").unwrap()
    ));
}
