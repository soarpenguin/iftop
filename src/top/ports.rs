use std::collections::HashMap;
use std::time::Instant;

use crate::flow::Snapshot;
use crate::services::service_name;
use crate::top::types::{rank, TopRow};

#[must_use]
pub fn top_ports(snap: &Snapshot, now: Instant, n: usize) -> Vec<TopRow> {
    let mut map: HashMap<u16, (u64, f64, f64, f64)> = HashMap::new();
    for s in &snap.flows {
        if s.key.port_a != 0 {
            let e_a = map.entry(s.key.port_a).or_insert((0, 0.0, 0.0, 0.0));
            e_a.0 += s.bytes_a_to_b;
            e_a.1 += s.rate_a_to_b_2s.rate(now);
            e_a.2 += s.rate_a_to_b_10s.rate(now);
            e_a.3 += s.rate_a_to_b_40s.rate(now);
        }
        if s.key.port_b != 0 {
            let e_b = map.entry(s.key.port_b).or_insert((0, 0.0, 0.0, 0.0));
            e_b.0 += s.bytes_b_to_a;
            e_b.1 += s.rate_b_to_a_2s.rate(now);
            e_b.2 += s.rate_b_to_a_10s.rate(now);
            e_b.3 += s.rate_b_to_a_40s.rate(now);
        }
    }
    rank(map, n, |p| {
        service_name(p, 0).map_or_else(|| p.to_string(), |name| format!("{p} ({name})"))
    })
}
