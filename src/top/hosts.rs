use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use crate::flow::{FlowStats, Snapshot};
use crate::top::types::{rank, TopRow};

#[must_use]
pub fn top_hosts(snap: &Snapshot, now: Instant, n: usize) -> Vec<TopRow> {
    let mut map: HashMap<IpAddr, (u64, f64, f64, f64)> = HashMap::new();
    for s in &snap.flows {
        accumulate_host(&mut map, s, now);
    }
    rank(map, n, |ip| ip.to_string())
}

fn accumulate_host(map: &mut HashMap<IpAddr, (u64, f64, f64, f64)>, s: &FlowStats, now: Instant) {
    let e_a = map.entry(s.key.a).or_insert((0, 0.0, 0.0, 0.0));
    e_a.0 += s.bytes_a_to_b;
    e_a.1 += s.rate_a_to_b_2s.rate(now);
    e_a.2 += s.rate_a_to_b_10s.rate(now);
    e_a.3 += s.rate_a_to_b_40s.rate(now);

    let e_b = map.entry(s.key.b).or_insert((0, 0.0, 0.0, 0.0));
    e_b.0 += s.bytes_b_to_a;
    e_b.1 += s.rate_b_to_a_2s.rate(now);
    e_b.2 += s.rate_b_to_a_10s.rate(now);
    e_b.3 += s.rate_b_to_a_40s.rate(now);
}
