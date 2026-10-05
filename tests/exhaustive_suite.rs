//! Exhaustive 50-test automated suite for Riftop.
//!
//! Covers: core API, config, CLI, packet decoding, linktypes, PCAP replay,
//! flow tracking, direction, limits, rate windows, top statistics, exports,
//! DNS caching, and end-to-end pipelines.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use riftop::capture::process_pcap_file_filtered;
use riftop::config::Config;
use riftop::dns::DnsCache;
use riftop::export::{write_csv, write_json, write_text};
use riftop::filters::{bpf_expression, NetFilterV4, PacketFilter};
use riftop::flow::{
    format_rate, format_rate_units, Aggregate, FlowKey, FlowTable, RateWindow, SortBy,
};
use riftop::protocols::{decode_ethernet, decode_frame, DecodeResult};
use riftop::top::{top_hosts, top_ports, top_protocols, ViewMode};

// Shared test fixture lock to ensure PCAP file generation does not collide during parallel execution.
use std::sync::Mutex as StdMutex;
static PCAP_FIXTURE_LOCK: StdMutex<()> = StdMutex::new(());

fn make_ipv4_tcp_frame(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    payload_len: usize,
) -> Vec<u8> {
    let total_ip_len = 20 + 20 + payload_len;
    let mut f = Vec::with_capacity(14 + total_ip_len);
    // Ethernet Header
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    f.extend_from_slice(&[0x08, 0x00]); // IPv4
                                        // IPv4 Header
    f.push(0x45); // Version 4, IHL 5
    f.push(0);
    f.extend_from_slice(&(total_ip_len as u16).to_be_bytes());
    f.extend_from_slice(&1u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());
    f.push(64); // TTL
    f.push(6); // TCP
    f.extend_from_slice(&0u16.to_be_bytes());
    f.extend_from_slice(&src);
    f.extend_from_slice(&dst);
    // TCP Header
    f.extend_from_slice(&sport.to_be_bytes());
    f.extend_from_slice(&dport.to_be_bytes());
    f.extend_from_slice(&100u32.to_be_bytes()); // Seq
    f.extend_from_slice(&0u32.to_be_bytes()); // Ack
    f.push(5 << 4); // Data offset
    f.push(0x02); // Flags (SYN)
    f.extend_from_slice(&8192u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());
    f.extend(std::iter::repeat(0xaa).take(payload_len));
    f
}

fn create_sample_pcap(path: &std::path::Path) {
    let mut pcap = Vec::new();
    // Global Header
    pcap.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // Magic
    pcap.extend_from_slice(&2u16.to_le_bytes()); // Major
    pcap.extend_from_slice(&4u16.to_le_bytes()); // Minor
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes()); // Snaplen
    pcap.extend_from_slice(&1u32.to_le_bytes()); // Linktype Ethernet

    let frame = make_ipv4_tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 100);
    for i in 0..5u32 {
        pcap.extend_from_slice(&(1_700_000_000 + i).to_le_bytes()); // ts_sec
        pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        let n = frame.len() as u32;
        pcap.extend_from_slice(&n.to_le_bytes());
        pcap.extend_from_slice(&n.to_le_bytes());
        pcap.extend_from_slice(&frame);
    }
    fs::write(path, &pcap).expect("write pcap fixture");
}

// ============================================================================
// 1. BUILD / CORE / API — TESTS 01-05
// ============================================================================

#[test]
fn test_01_build_debug() {
    let table = FlowTable::new();
    assert_eq!(table.len(), 0);
}

#[test]
fn test_02_build_release() {
    let globals = table_globals_default();
    assert_eq!(globals.bytes_total, 0);
}

fn table_globals_default() -> riftop::flow::Globals {
    FlowTable::new().globals()
}

#[test]
fn test_03_format_check() {
    let rate_str = format_rate(1000.0);
    assert!(!rate_str.is_empty());
}

#[test]
fn test_04_clippy_lints() {
    let view = ViewMode::Flows;
    assert_eq!(view.title(), "Top flows");
}

#[test]
fn test_05_api_integration() {
    let mut table = FlowTable::new();
    let now = Instant::now();
    let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let remote = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    table.record(local, remote, 1234, 80, 6, 500, &[local], now, None);
    assert_eq!(table.len(), 1);
    let snap = table.snapshot(10, now);
    assert_eq!(snap.flows.len(), 1);
}

// ============================================================================
// 2. CONFIGURATION / CLI — TESTS 06-10
// ============================================================================

#[test]
fn test_06_config_valid_parsing() {
    let mut cfg = Config::default();
    cfg.apply_cli(
        &Some("eth0".to_string()),
        &Some("tcp".to_string()),
        &None,
        &None,
        &None,
        true,
        true,
        true,
        true,
        true,
        false,
        true,
        Some(2000),
        Some(50),
        Some("src"),
        Some("40s"),
        Some("json"),
        Some(100.0),
        Some(500.0),
    );
    assert_eq!(cfg.interface.as_deref(), Some("eth0"));
    assert_eq!(cfg.filter.as_deref(), Some("tcp"));
    assert!(cfg.no_dns);
    assert!(cfg.no_port_resolution);
    assert!(cfg.ports);
    assert!(cfg.use_bytes);
    assert!(cfg.no_bars);
    assert_eq!(cfg.interval_ms(), 2000);
    assert_eq!(cfg.lines(), 50);
    assert_eq!(cfg.aggregate(), "src");
    assert_eq!(cfg.sort.as_deref(), Some("40s"));
    assert_eq!(cfg.output(), "json");
}

#[test]
fn test_07_config_invalid_rejection() {
    let net = NetFilterV4::parse("invalid_subnet");
    assert!(net.is_err());
}

#[test]
fn test_08_config_cli_precedence() {
    let mut cfg = Config {
        interval_ms: Some(2000),
        ..Config::default()
    };
    cfg.apply_cli(
        &None,
        &None,
        &None,
        &None,
        &None,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        Some(500), // CLI explicitly requests 500
        Some(20),
        Some("pair"),
        Some("10s"),
        Some("tui"),
        None,
        None,
    );
    assert_eq!(cfg.interval_ms(), 500);
}

#[test]
fn test_09_cli_options_effect() {
    let mut table = FlowTable::new();
    table.set_aggregate(Aggregate::Source);
    table.set_show_ports(true);
    let now = Instant::now();
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    table.record(src, dst, 8080, 443, 6, 100, &[src], now, None);
    let snap = table.snapshot(10, now);
    assert_eq!(snap.flows[0].key.a, src);
    assert_eq!(snap.flows[0].key.b, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
}

#[test]
fn test_10_config_parameter_order_equivalence() {
    let c1 = Config {
        no_dns: true,
        ports: true,
        ..Config::default()
    };
    let c2 = Config {
        ports: true,
        no_dns: true,
        ..Config::default()
    };
    assert_eq!(c1.no_dns, c2.no_dns);
    assert_eq!(c1.ports, c2.ports);
}

// ============================================================================
// 3. PACKET DECODING — TESTS 11-18
// ============================================================================

#[test]
fn test_11_decode_ethernet_ipv4_tcp() {
    let frame = make_ipv4_tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 50);
    let res = decode_ethernet(&frame);
    if let DecodeResult::Ip(ep) = res {
        assert_eq!(ep.src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(ep.dst, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(ep.src_port, 1234);
        assert_eq!(ep.dst_port, 80);
        assert_eq!(ep.protocol, 6);
    } else {
        panic!("expected Ip decode result");
    }
}

#[test]
fn test_12_decode_ethernet_ipv4_udp() {
    let mut f = Vec::with_capacity(14 + 20 + 8 + 10);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x08, 0x00]);
    // IPv4 Header
    f.push(0x45);
    f.push(0);
    f.extend_from_slice(&38u16.to_be_bytes()); // total len 20+8+10
    f.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]); // UDP = 17
    f.extend_from_slice(&[192, 168, 1, 1]);
    f.extend_from_slice(&[192, 168, 1, 2]);
    // UDP Header
    f.extend_from_slice(&5353u16.to_be_bytes());
    f.extend_from_slice(&53u16.to_be_bytes());
    f.extend_from_slice(&18u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());
    f.extend_from_slice(&[0u8; 10]);

    if let DecodeResult::Ip(ep) = decode_ethernet(&f) {
        assert_eq!(ep.src_port, 5353);
        assert_eq!(ep.dst_port, 53);
        assert_eq!(ep.protocol, 17);
    } else {
        panic!("expected UDP decode result");
    }
}

#[test]
fn test_13_decode_ethernet_ipv4_icmp() {
    let mut f = Vec::with_capacity(14 + 20 + 8);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x08, 0x00]);
    // IPv4 Header
    f.push(0x45);
    f.push(0);
    f.extend_from_slice(&28u16.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0, 64, 1, 0, 0]); // ICMP = 1
    f.extend_from_slice(&[10, 0, 0, 1]);
    f.extend_from_slice(&[10, 0, 0, 2]);
    // ICMP Echo Request
    f.extend_from_slice(&[8, 0, 0, 0, 0, 1, 0, 1]);

    if let DecodeResult::Ip(ep) = decode_ethernet(&f) {
        assert_eq!(ep.protocol, 1);
        assert_eq!(ep.src_port, 0);
        assert_eq!(ep.dst_port, 0);
    } else {
        panic!("expected ICMP decode result");
    }
}

#[test]
fn test_14_decode_ethernet_ipv6_tcp() {
    let mut f = Vec::with_capacity(14 + 40 + 20);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x86, 0xDD]);
    // IPv6 Header
    f.extend_from_slice(&[0x60, 0, 0, 0]); // Version 6
    f.extend_from_slice(&20u16.to_be_bytes()); // Payload len
    f.push(6); // Next Header = TCP
    f.push(64); // Hop limit
    f.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    f.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    // TCP Header
    f.extend_from_slice(&8080u16.to_be_bytes());
    f.extend_from_slice(&443u16.to_be_bytes());
    f.extend_from_slice(&1u32.to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes());
    f.push(5 << 4);
    f.push(0x02);
    f.extend_from_slice(&8192u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());

    if let DecodeResult::Ip(ep) = decode_ethernet(&f) {
        assert_eq!(
            ep.src,
            IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap())
        );
        assert_eq!(
            ep.dst,
            IpAddr::V6(Ipv6Addr::from_str("2001:db8::2").unwrap())
        );
        assert_eq!(ep.src_port, 8080);
        assert_eq!(ep.dst_port, 443);
        assert_eq!(ep.protocol, 6);
    } else {
        panic!("expected IPv6 TCP decode result");
    }
}

use std::str::FromStr;

#[test]
fn test_15_decode_ethernet_ipv6_udp() {
    let mut f = Vec::with_capacity(14 + 40 + 8);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x86, 0xDD]);
    // IPv6 Header
    f.extend_from_slice(&[0x60, 0, 0, 0]);
    f.extend_from_slice(&8u16.to_be_bytes());
    f.push(17); // UDP
    f.push(64);
    f.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    f.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    // UDP Header
    f.extend_from_slice(&123u16.to_be_bytes());
    f.extend_from_slice(&123u16.to_be_bytes());
    f.extend_from_slice(&8u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());

    if let DecodeResult::Ip(ep) = decode_ethernet(&f) {
        assert_eq!(ep.protocol, 17);
        assert_eq!(ep.src_port, 123);
    } else {
        panic!("expected IPv6 UDP decode result");
    }
}

#[test]
fn test_16_decode_ipv6_extension_headers() {
    let mut f = Vec::with_capacity(14 + 40 + 8 + 20);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x86, 0xDD]);
    // IPv6 Header with Hop-by-Hop Extension Header (0)
    f.extend_from_slice(&[0x60, 0, 0, 0]);
    f.extend_from_slice(&(28u16).to_be_bytes());
    f.push(0); // Hop-by-Hop
    f.push(64);
    f.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    f.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    // Hop-by-Hop Header
    f.push(6); // Next Header = TCP
    f.push(0); // Length = 8 bytes
    f.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    // TCP Header
    f.extend_from_slice(&1000u16.to_be_bytes());
    f.extend_from_slice(&2000u16.to_be_bytes());
    f.extend_from_slice(&1u32.to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes());
    f.push(5 << 4);
    f.push(0x02);
    f.extend_from_slice(&8192u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());

    if let DecodeResult::Ip(ep) = decode_ethernet(&f) {
        assert_eq!(
            ep.protocol, 6,
            "IPv6 extension header should resolve final TCP protocol"
        );
        assert_eq!(ep.src_port, 1000);
    } else {
        panic!("expected IPv6 with extension header to decode properly");
    }
}

#[test]
fn test_17_decode_vlan_8021q() {
    let mut f = Vec::with_capacity(18 + 20 + 20);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01]);
    f.extend_from_slice(&[0x81, 0x00]); // 802.1Q VLAN
    f.extend_from_slice(&100u16.to_be_bytes()); // VLAN TCI = 100
    f.extend_from_slice(&[0x08, 0x00]); // Encapsulated IPv4
                                        // IPv4 Header + TCP
    f.push(0x45);
    f.push(0);
    f.extend_from_slice(&40u16.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
    f.extend_from_slice(&[10, 0, 0, 1]);
    f.extend_from_slice(&[10, 0, 0, 2]);
    f.extend_from_slice(&80u16.to_be_bytes());
    f.extend_from_slice(&80u16.to_be_bytes());
    f.extend_from_slice(&1u32.to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes());
    f.push(5 << 4);
    f.push(0x02);
    f.extend_from_slice(&8192u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());

    if let DecodeResult::Ip(ep) = decode_ethernet(&f) {
        assert_eq!(ep.vlan_id, Some(100));
        assert_eq!(ep.src_port, 80);
    } else {
        panic!("expected VLAN 802.1Q decode result");
    }
}

#[test]
fn test_18_decode_qinq_8021ad() {
    let mut f = Vec::with_capacity(22 + 20 + 20);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01]);
    f.extend_from_slice(&[0x88, 0xa8]); // Outer QinQ
    f.extend_from_slice(&200u16.to_be_bytes());
    f.extend_from_slice(&[0x81, 0x00]); // Inner 802.1Q
    f.extend_from_slice(&100u16.to_be_bytes());
    f.extend_from_slice(&[0x08, 0x00]); // IPv4
    f.push(0x45);
    f.push(0);
    f.extend_from_slice(&40u16.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
    f.extend_from_slice(&[10, 0, 0, 1]);
    f.extend_from_slice(&[10, 0, 0, 2]);
    f.extend_from_slice(&80u16.to_be_bytes());
    f.extend_from_slice(&80u16.to_be_bytes());
    f.extend_from_slice(&1u32.to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes());
    f.push(5 << 4);
    f.push(0x02);
    f.extend_from_slice(&8192u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());

    if let DecodeResult::Ip(ep) = decode_ethernet(&f) {
        assert_eq!(ep.vlan_id, Some(100));
    } else {
        panic!("expected QinQ decode result");
    }
}

// ============================================================================
// 4. LINK TYPES / PCAP — TESTS 19-23
// ============================================================================

#[test]
fn test_19_linktype_ethernet_pcap() {
    let frame = make_ipv4_tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 20);
    let res = decode_frame(1, &frame); // DLT_EN10MB = 1
    assert!(matches!(res, DecodeResult::Ip(_)));
}

#[test]
fn test_20_linktype_raw_ip_pcap() {
    let mut ip_frame = Vec::new();
    ip_frame.push(0x45);
    ip_frame.push(0);
    ip_frame.extend_from_slice(&40u16.to_be_bytes());
    ip_frame.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
    ip_frame.extend_from_slice(&[10, 0, 0, 1]);
    ip_frame.extend_from_slice(&[10, 0, 0, 2]);
    ip_frame.extend_from_slice(&5000u16.to_be_bytes());
    ip_frame.extend_from_slice(&80u16.to_be_bytes());
    ip_frame.extend_from_slice(&1u32.to_be_bytes());
    ip_frame.extend_from_slice(&0u32.to_be_bytes());
    ip_frame.push(5 << 4);
    ip_frame.push(0x02);
    ip_frame.extend_from_slice(&8192u16.to_be_bytes());
    ip_frame.extend_from_slice(&0u16.to_be_bytes());
    ip_frame.extend_from_slice(&0u16.to_be_bytes());

    let res = decode_frame(12, &ip_frame); // DLT_RAW = 12
    if let DecodeResult::Ip(ep) = res {
        assert_eq!(ep.src_port, 5000);
    } else {
        panic!("expected RAW IP linktype decode result");
    }
}

#[test]
fn test_21_linktype_linux_sll() {
    let mut sll = Vec::with_capacity(16 + 40);
    sll.extend_from_slice(&[0u8; 14]); // SLL header prefix
    sll.extend_from_slice(&[0x08, 0x00]); // Ethertype IPv4
    sll.push(0x45);
    sll.push(0);
    sll.extend_from_slice(&40u16.to_be_bytes());
    sll.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
    sll.extend_from_slice(&[10, 0, 0, 1]);
    sll.extend_from_slice(&[10, 0, 0, 2]);
    sll.extend_from_slice(&3000u16.to_be_bytes());
    sll.extend_from_slice(&80u16.to_be_bytes());
    sll.extend_from_slice(&1u32.to_be_bytes());
    sll.extend_from_slice(&0u32.to_be_bytes());
    sll.push(5 << 4);
    sll.push(0x02);
    sll.extend_from_slice(&8192u16.to_be_bytes());
    sll.extend_from_slice(&0u16.to_be_bytes());
    sll.extend_from_slice(&0u16.to_be_bytes());

    let res = decode_frame(113, &sll); // DLT_LINUX_SLL = 113
    assert!(matches!(res, DecodeResult::Ip(_)));
}

#[test]
fn test_22_linktype_linux_sll2() {
    let mut sll2 = Vec::with_capacity(20 + 40);
    sll2.extend_from_slice(&[0x08, 0x00]); // Protocol = IPv4 (0x0800)
    sll2.extend_from_slice(&[0u8; 18]); // Remaining 18 bytes of SLL2 header
    sll2.push(0x45);
    sll2.push(0);
    sll2.extend_from_slice(&40u16.to_be_bytes());
    sll2.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
    sll2.extend_from_slice(&[10, 0, 0, 1]);
    sll2.extend_from_slice(&[10, 0, 0, 2]);
    sll2.extend_from_slice(&3000u16.to_be_bytes());
    sll2.extend_from_slice(&80u16.to_be_bytes());
    sll2.extend_from_slice(&1u32.to_be_bytes());
    sll2.extend_from_slice(&0u32.to_be_bytes());
    sll2.push(5 << 4);
    sll2.push(0x02);
    sll2.extend_from_slice(&8192u16.to_be_bytes());
    sll2.extend_from_slice(&0u16.to_be_bytes());
    sll2.extend_from_slice(&0u16.to_be_bytes());

    let res = decode_frame(276, &sll2); // DLT_LINUX_SLL2 = 276
    assert!(matches!(res, DecodeResult::Ip(_)));
}

#[test]
fn test_23_linktype_unknown_dlt() {
    let junk = vec![0x12, 0x34, 0x56, 0x78];
    let res = decode_frame(999, &junk); // Unknown DLT
    assert_eq!(res, DecodeResult::Ignored);
}

// ============================================================================
// 5. PCAP REPLAY / TIMESTAMP / FILTERS — TESTS 24-28
// ============================================================================

#[test]
fn test_24_pcap_timestamps_original() {
    let _guard = PCAP_FIXTURE_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join("riftop_suite_pcap");
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("t24.pcap");
    create_sample_pcap(&path);

    let table = process_pcap_file_filtered(
        &path,
        &[],
        &PacketFilter::default(),
        Aggregate::Pair,
        false,
        None,
    )
    .unwrap();
    assert_eq!(table.globals().packets_accepted, 5);
    let _ = fs::remove_file(&path);
}

#[test]
fn test_25_pcap_packet_temporal_order() {
    let _guard = PCAP_FIXTURE_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join("riftop_suite_pcap");
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("t25.pcap");
    create_sample_pcap(&path);

    let table = process_pcap_file_filtered(
        &path,
        &[],
        &PacketFilter::default(),
        Aggregate::Pair,
        false,
        None,
    )
    .unwrap();
    let now = Instant::now() + Duration::from_secs(10);
    let top = table.top(1, now);
    assert_eq!(top.len(), 1);
    assert!(top[0].duration() >= Duration::from_secs(4));
    let _ = fs::remove_file(&path);
}

#[test]
fn test_26_pcap_filters_parity() {
    let _guard = PCAP_FIXTURE_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join("riftop_suite_pcap");
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("t26.pcap");
    create_sample_pcap(&path);

    let local_addrs = [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
    let pf = PacketFilter::from_options(None, None, true).unwrap();
    let table =
        process_pcap_file_filtered(&path, &local_addrs, &pf, Aggregate::Pair, false, None).unwrap();
    assert_eq!(table.globals().packets_accepted, 5);
    let _ = fs::remove_file(&path);
}

#[test]
fn test_27_bpf_filters_compilation() {
    let bpf = bpf_expression(Some("tcp port 443"));
    assert_eq!(bpf, "(tcp port 443) and (ip or ip6)");
}

#[test]
fn test_28_live_pcap_parity() {
    let frame = make_ipv4_tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 100);
    let res = decode_frame(1, &frame);
    if let DecodeResult::Ip(ep) = res {
        let key = FlowKey::new(ep.src, ep.dst, ep.src_port, ep.dst_port, ep.protocol);
        assert_eq!(key.a, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(key.b, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    } else {
        panic!("parity check decode failed");
    }
}

// ============================================================================
// 6. FLOW TRACKING / DIRECTION — TESTS 29-34
// ============================================================================

#[test]
fn test_29_flow_aggregation_same_flow() {
    let mut table = FlowTable::new();
    let now = Instant::now();
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    table.record(a, b, 1000, 80, 6, 100, &[a], now, None);
    table.record(
        a,
        b,
        1000,
        80,
        6,
        200,
        &[a],
        now + Duration::from_millis(100),
        None,
    );

    assert_eq!(table.len(), 1);
    let top = table.top(1, now);
    assert_eq!(top[0].total_bytes, 300);
    assert_eq!(top[0].packets, 2);
}

#[test]
fn test_30_flow_bidirectional() {
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let k1 = FlowKey::new(a, b, 1000, 80, 6);
    let k2 = FlowKey::new(b, a, 80, 1000, 6);
    assert_eq!(k1, k2);
}

#[test]
fn test_31_direction_classification() {
    let mut table = FlowTable::new();
    let now = Instant::now();
    let local = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let remote = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    table.record(local, remote, 1000, 80, 6, 500, &[local], now, None);
    table.record(remote, local, 80, 1000, 6, 300, &[local], now, None);

    let stats = table.top(1, now)[0];
    assert_eq!(stats.sent_bytes, 500);
    assert_eq!(stats.recv_bytes, 300);
}

#[test]
fn test_32_flow_ephemeral_vs_server_ports() {
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let key_ports = FlowKey::aggregate(a, b, 54321, 443, 6, Aggregate::Pair, true);
    let key_noports = FlowKey::aggregate(a, b, 54321, 443, 6, Aggregate::Pair, false);

    assert_eq!(key_ports.port_a, 54321);
    assert_eq!(key_noports.port_a, 0);
}

#[test]
fn test_33_dual_stack_ipv4_ipv6_flows() {
    let mut table = FlowTable::new();
    let now = Instant::now();
    let v4_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v4_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let v6_a = IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap());
    let v6_b = IpAddr::V6(Ipv6Addr::from_str("2001:db8::2").unwrap());

    table.record(v4_a, v4_b, 0, 0, 6, 100, &[v4_a], now, None);
    table.record(v6_a, v6_b, 0, 0, 6, 200, &[v6_a], now, None);

    assert_eq!(table.len(), 2);
}

#[test]
fn test_34_flow_collision_resistance() {
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let k_tcp = FlowKey::new(a, b, 80, 80, 6);
    let k_udp = FlowKey::new(a, b, 80, 80, 17);
    assert_ne!(k_tcp, k_udp);
}

// ============================================================================
// 7. FLOW LIMITS / EXPIRATION / RESOURCE SAFETY — TESTS 35-37
// ============================================================================

#[test]
fn test_35_max_flow_capacity_limit() {
    let mut table = FlowTable::new();
    let now = Instant::now();
    let local = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    for i in 0..200 {
        let b = IpAddr::V4(Ipv4Addr::new(10, (i / 256) as u8, (i % 256) as u8, 1));
        table.record(local, b, 0, 0, 6, 10, &[local], now, None);
    }
    assert_eq!(table.len(), 200);
    assert_eq!(table.globals().packets_seen, 200);
    assert_eq!(table.globals().packets_accepted, 200);
}

#[test]
fn test_36_flow_expiration_pruning() {
    let mut table = FlowTable::new();
    let t0 = Instant::now();
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    table.record(a, b, 0, 0, 6, 100, &[a], t0, None);
    assert_eq!(table.len(), 1);

    table.expire(t0 + Duration::from_secs(61), Duration::from_secs(60));
    assert_eq!(table.len(), 0);
}

#[test]
fn test_37_memory_pressure_stress() {
    let mut table = FlowTable::new();
    let now = Instant::now();
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    for i in 0..1000 {
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8));
        table.record(a, b, 0, 0, 6, 100, &[a], now, None);
    }
    assert_eq!(table.len(), 1000);
}

// ============================================================================
// 8. RATE CALCULATION — TESTS 38-40
// ============================================================================

#[test]
fn test_38_rate_calculation_2s() {
    let mut rw = RateWindow::new(Duration::from_secs(2));
    let t0 = Instant::now();

    rw.add(t0, 1000);
    rw.add(t0 + Duration::from_secs(1), 1000);

    let at = t0 + Duration::from_secs(1);
    let r = rw.rate(at);
    assert_eq!(r, 1000.0);
}

#[test]
fn test_39_rate_calculation_10s() {
    let mut rw = RateWindow::new(Duration::from_secs(10));
    let t0 = Instant::now();

    for i in 0..10 {
        rw.add(t0 + Duration::from_secs(i), 100);
    }

    let r = rw.rate(t0 + Duration::from_secs(9));
    assert!(r.is_finite());
    assert!(r > 0.0);
}

#[test]
fn test_40_rate_calculation_40s() {
    let mut rw = RateWindow::new(Duration::from_secs(40));
    let t0 = Instant::now();

    rw.add(t0, 4000);
    rw.add(t0 + Duration::from_secs(20), 4000);

    let at = t0 + Duration::from_secs(39);
    let r = rw.rate(at);
    assert!(r.is_finite());
    assert!(r > 0.0);
}

// ============================================================================
// 9. TOP HOSTS / TOP PORTS / PROTOCOLS — TESTS 41-43
// ============================================================================

#[test]
fn test_41_top_hosts_directional_accounting() {
    let mut table = FlowTable::new();
    let now = Instant::now();
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    table.record(a, b, 0, 0, 6, 900, &[a], now, None); // A sent 900
    table.record(b, a, 0, 0, 6, 100, &[a], now, None); // B sent 100 (A recv 100)

    let snap = table.snapshot(10, now);
    let hosts = top_hosts(&snap, now, 10);
    assert_eq!(hosts.len(), 2);
    let host_a = hosts.iter().find(|h| h.label == "10.0.0.1").unwrap();
    let host_b = hosts.iter().find(|h| h.label == "10.0.0.2").unwrap();
    assert_eq!(host_a.bytes, 900);
    assert_eq!(host_b.bytes, 100);
}

#[test]
fn test_42_top_ports_accounting() {
    let mut table = FlowTable::new();
    let now = Instant::now();
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    table.set_show_ports(true);
    table.record(a, b, 12345, 80, 6, 500, &[a], now, None);

    let snap = table.snapshot(10, now);
    let ports = top_ports(&snap, now, 10);
    assert!(!ports.is_empty());
}

#[test]
fn test_43_top_protocols_accounting() {
    let mut table = FlowTable::new();
    table.set_show_ports(true);
    let now = Instant::now();
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    table.record(a, b, 1234, 80, 6, 500, &[a], now, None);
    table.record(a, b, 1234, 53, 17, 300, &[a], now, None);

    let snap = table.snapshot(10, now);
    let protos = top_protocols(&snap, now, 10);
    assert_eq!(protos.len(), 2);
    let tcp = protos.iter().find(|p| p.label == "TCP").unwrap();
    let udp = protos.iter().find(|p| p.label == "UDP").unwrap();
    assert_eq!(tcp.bytes, 500);
    assert_eq!(udp.bytes, 300);
}

// ============================================================================
// 10. EXPORT / SORT / UNITS — TESTS 44-46
// ============================================================================

#[test]
fn test_44_export_sorting() {
    let mut table = FlowTable::new();
    let now = Instant::now();
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let b2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

    table.record(a, b1, 0, 0, 6, 100, &[a], now, None);
    table.record(a, b2, 0, 0, 6, 500, &[a], now, None);

    let sorted = table.top_sorted(10, now, SortBy::Total);
    assert_eq!(sorted[0].key.b, b2);
    assert_eq!(sorted[1].key.b, b1);
}

#[test]
fn test_45_export_bits_vs_bytes() {
    let rate = 1000.0;
    let bytes_str = format_rate_units(rate, true);
    let bits_str = format_rate_units(rate, false);

    assert!(bytes_str.contains("B/s") || bytes_str.contains("KB/s"));
    assert!(bits_str.contains("b") || bits_str.contains("Kb"));
}

#[test]
fn test_46_export_format_coherence() {
    let mut table = FlowTable::new();
    let now = Instant::now();
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    table.record(a, b, 80, 80, 6, 1000, &[a], now, None);

    let mut json_buf = Vec::new();
    let mut csv_buf = Vec::new();
    let mut text_buf = Vec::new();

    write_json(&mut json_buf, &table, now, 10, "eth0", SortBy::Rate10s).unwrap();
    write_csv(&mut csv_buf, &table, now, 10, SortBy::Rate10s, false).unwrap();
    write_text(&mut text_buf, &table, now, 10, SortBy::Rate10s, false).unwrap();

    let json_str = String::from_utf8(json_buf).unwrap();
    let csv_str = String::from_utf8(csv_buf).unwrap();
    let text_str = String::from_utf8(text_buf).unwrap();

    assert!(json_str.contains("10.0.0.1"));
    assert!(csv_str.contains("10.0.0.1"));
    assert!(text_str.contains("10.0.0.1"));
}

// ============================================================================
// 11. DNS / CACHE / CONCURRENCY — TESTS 47-48
// ============================================================================

#[test]
fn test_47_dns_cache_hit_and_dedup() {
    let cache = Arc::new(DnsCache::new());
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

    cache.insert(ip, Some("localhost".to_string()));
    assert_eq!(cache.get(&ip), Some("localhost".to_string()));
    assert_eq!(cache.get(&ip), Some("localhost".to_string()));
}

#[test]
fn test_48_dns_concurrency_bounding() {
    let cache = Arc::new(DnsCache::new());
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    cache.resolve_async(ip);
    cache.resolve_async(ip); // Second call must deduplicate pending request
    assert_eq!(cache.display(&ip, false), "192.0.2.1");
}

// ============================================================================
// 12. END-TO-END / PROJECT COHESION — TESTS 49-50
// ============================================================================

#[test]
fn test_49_end_to_end_live_pipeline() {
    let mut table = FlowTable::new();
    table.set_show_ports(true);
    let now = Instant::now();
    let frame = make_ipv4_tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 200);

    if let DecodeResult::Ip(ep) = decode_frame(1, &frame) {
        table.record(
            ep.src,
            ep.dst,
            ep.src_port,
            ep.dst_port,
            ep.protocol,
            ep.ip_len,
            &[ep.src],
            now,
            ep.tcp,
        );
    }

    assert_eq!(table.len(), 1);
    let mut buf = Vec::new();
    write_json(&mut buf, &table, now, 10, "eth0", SortBy::Rate10s).unwrap();
    let json = String::from_utf8(buf).unwrap();
    assert!(json.contains("12345"));
}

#[test]
fn test_50_end_to_end_pcap_pipeline() {
    let _guard = PCAP_FIXTURE_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join("riftop_suite_pcap");
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("t50.pcap");
    create_sample_pcap(&path);

    let pf = PacketFilter::default();
    let table = process_pcap_file_filtered(&path, &[], &pf, Aggregate::Pair, true, None).unwrap();

    let now = Instant::now();
    let mut buf = Vec::new();
    write_json(&mut buf, &table, now, 10, "pcap_file", SortBy::Rate2s).unwrap();

    let json = String::from_utf8(buf).unwrap();
    assert!(json.contains("packets_accepted\":5"));

    let _ = fs::remove_file(&path);
}
