use std::collections::HashMap;
use std::time::Instant;

use crate::flow::Snapshot;
use crate::top::types::{rank, TopRow};

#[must_use]
pub fn top_protocols(snap: &Snapshot, now: Instant, n: usize) -> Vec<TopRow> {
    let mut map: HashMap<u8, (u64, f64, f64, f64)> = HashMap::new();
    for s in &snap.flows {
        let e = map.entry(s.key.protocol).or_insert((0, 0.0, 0.0, 0.0));
        e.0 += s.total_bytes;
        e.1 += s.rate_2s(now);
        e.2 += s.rate_10s(now);
        e.3 += s.rate_40s(now);
    }
    rank(map, n, |p| proto_name(p).to_string())
}

const fn proto_name(p: u8) -> &'static str {
    match p {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        0 => "any",
        _ => "other",
    }
}
