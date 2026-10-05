//! Regression R1 (rate windows) and R4 (direction from local address).

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use riftop::capture::process_pcap_file;
use riftop::flow::{FlowKey, FlowTable};
use riftop::protocols::{decode_ethernet, DecodeResult};

fn local_host() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
}

fn remote_host() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
}

fn eth_ipv4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, ip_total_len: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + ip_total_len as usize);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    f.extend_from_slice(&[0x08, 0x00]);
    f.push(0x45);
    f.push(0);
    f.extend_from_slice(&ip_total_len.to_be_bytes());
    f.extend_from_slice(&0x1234u16.to_be_bytes());
    f.extend_from_slice(&0x4000u16.to_be_bytes());
    f.push(64);
    f.push(6);
    f.extend_from_slice(&0u16.to_be_bytes());
    f.extend_from_slice(&src);
    f.extend_from_slice(&dst);
    f.extend_from_slice(&sport.to_be_bytes());
    f.extend_from_slice(&dport.to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes());
    f.push(5 << 4);
    f.push(0x18);
    f.extend_from_slice(&8192u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());
    let payload = ip_total_len.saturating_sub(40) as usize;
    f.extend(std::iter::repeat(0u8).take(payload));
    f
}

fn pcap_record(ts_sec: u32, frame: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(16 + frame.len());
    r.extend_from_slice(&ts_sec.to_le_bytes());
    r.extend_from_slice(&0u32.to_le_bytes());
    let n = frame.len() as u32;
    r.extend_from_slice(&n.to_le_bytes());
    r.extend_from_slice(&n.to_le_bytes());
    r.extend_from_slice(frame);
    r
}

use std::sync::Mutex as StdMutex;

static FIXTURE_LOCK: StdMutex<()> = StdMutex::new(());

fn materialize_fixture() -> PathBuf {
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes());

    let a = [10, 0, 0, 1];
    let b = [10, 0, 0, 2];
    for i in 0..5u32 {
        let frame = eth_ipv4_tcp(a, b, 40000, 80, 100);
        pcap.extend_from_slice(&pcap_record(1_700_000_000 + i, &frame));
    }
    for i in 0..3u32 {
        let frame = eth_ipv4_tcp(b, a, 80, 40000, 200);
        pcap.extend_from_slice(&pcap_record(1_700_000_010 + i, &frame));
    }
    let mut garbage = vec![0xffu8; 6];
    garbage.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    garbage.extend_from_slice(&[0x08, 0x06]);
    garbage.extend(std::iter::repeat(0u8).take(28));
    pcap.extend_from_slice(&pcap_record(1_700_000_020, &garbage));

    let dir = std::env::temp_dir().join("riftop_fixtures");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        panic!("failed to create temp dir: {e}");
    }
    let path = dir.join("r1_r4_flows.pcap");
    if let Err(e) = std::fs::write(&path, &pcap) {
        panic!("failed to write pcap: {e}");
    }
    path
}

#[test]
fn r4_direction_from_local_address() {
    let _guard = match FIXTURE_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let fixture = materialize_fixture();
    let table = process_pcap_file(fixture, &[local_host()]).expect("process pcap");
    assert_eq!(table.len(), 1, "one bidirectional flow expected");
    let stats = table.top(1, Instant::now())[0];
    assert_eq!(stats.sent_bytes, 500, "R4: sent must be 5×100 from local");
    assert_eq!(stats.recv_bytes, 600, "R4: recv must be 3×200 to local");
    assert_eq!(stats.total_bytes, 1100);
}

#[test]
fn r4_direction_swaps_when_local_is_remote() {
    let _guard = match FIXTURE_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let fixture = materialize_fixture();
    let table = process_pcap_file(fixture, &[remote_host()]).expect("process pcap");
    let stats = table.top(1, Instant::now())[0];
    assert_eq!(stats.sent_bytes, 600);
    assert_eq!(stats.recv_bytes, 500);
}

#[test]
fn r2_single_flow_key_for_pair() {
    let _guard = match FIXTURE_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let fixture = materialize_fixture();
    let table = process_pcap_file(fixture, &[local_host()]).expect("process pcap");
    assert_eq!(table.len(), 1);
    let key = &table.top(1, Instant::now())[0].key;
    let expected = FlowKey::new(local_host(), remote_host(), 40000, 80, 6);
    assert_eq!(key.a, expected.a);
    assert_eq!(key.b, expected.b);
}

#[test]
fn r6_non_ip_in_fixture_ignored() {
    let _guard = match FIXTURE_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let fixture = materialize_fixture();
    let table = process_pcap_file(fixture, &[local_host()]).expect("process pcap");
    assert_eq!(table.len(), 1);
    assert_eq!(decode_ethernet(&[0u8; 8]), DecodeResult::Ignored);
}

#[test]
fn r1_rate_windows_respect_sample_age() {
    let mut table = FlowTable::new();
    let t0 = Instant::now();
    let local = local_host();
    let remote = remote_host();

    table.record(local, remote, 0, 0, 1, 1000, &[local], t0, None);
    table.record(
        local,
        remote,
        0,
        0,
        1,
        1000,
        &[local],
        t0 + Duration::from_secs(1),
        None,
    );
    table.record(
        local,
        remote,
        0,
        0,
        1,
        5000,
        &[local],
        t0 + Duration::from_secs(30),
        None,
    );

    let at = t0 + Duration::from_secs(30);
    let stats = table.top(1, at)[0];
    let r2 = stats.rate_2s(at);
    let r40 = stats.rate_40s(at);
    assert!(r2.is_finite() && r40.is_finite());
    assert!(r2 > 0.0, "R1: positive 2s rate");
    assert!(r40 > 0.0, "R1: positive 40s rate");
}

#[test]
fn r1_offline_pcap_totals_and_rates() {
    let _guard = match FIXTURE_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let fixture = materialize_fixture();
    let table = process_pcap_file(fixture, &[local_host()]).expect("process pcap");
    let at = Instant::now() + Duration::from_secs(5);
    let stats = table.top(1, at)[0];
    assert_eq!(stats.total_bytes, 1100);
    assert_eq!(stats.sent_bytes + stats.recv_bytes, stats.total_bytes);
    assert!(stats.rate_2s(at).is_finite());
    assert!(stats.rate_10s(at).is_finite());
    assert!(stats.rate_40s(at).is_finite());
}
