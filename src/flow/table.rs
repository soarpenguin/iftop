use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::filters::PacketFilter;
use crate::flow::key::{Aggregate, FlowKey};
use crate::flow::stats::{Direction, FlowStats};
use crate::protocols::TcpFlags;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortBy {
    Rate2s,
    #[default]
    Rate10s,
    Rate40s,
    Source,
    Destination,
    Total,
}

impl SortBy {
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "2s" => Self::Rate2s,
            "40s" => Self::Rate40s,
            "source" | "src" => Self::Source,
            "destination" | "dst" => Self::Destination,
            "total" => Self::Total,
            _ => Self::Rate10s,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Globals {
    pub packets_seen: u64,
    pub packets_accepted: u64,
    pub bytes_total: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub flows: Vec<FlowStats>,
    pub globals: Globals,
    pub taken_at: Instant,
}

const MAX_FLOWS: usize = 100_000;

#[derive(Debug, Default)]
pub struct FlowTable {
    flows: HashMap<FlowKey, FlowStats>,
    globals: Globals,
    aggregate: Aggregate,
    show_ports: bool,
}

fn rate_ord(a: f64, b: f64) -> Ordering {
    b.partial_cmp(&a).unwrap_or(Ordering::Equal)
}

impl FlowTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_aggregate(&mut self, mode: Aggregate) {
        self.aggregate = mode;
    }
    pub fn set_show_ports(&mut self, show: bool) {
        self.show_ports = show;
    }
    #[must_use]
    pub fn globals(&self) -> Globals {
        self.globals.clone()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
        protocol: u8,
        bytes: u64,
        local_addrs: &[IpAddr],
        now: Instant,
        tcp: Option<TcpFlags>,
    ) {
        self.globals.packets_seen += 1;
        let key = FlowKey::aggregate(
            src,
            dst,
            sport,
            dport,
            protocol,
            self.aggregate,
            self.show_ports,
        );
        if !self.flows.contains_key(&key) && self.flows.len() >= MAX_FLOWS {
            self.expire(now, Duration::from_secs(30));
            if self.flows.len() >= MAX_FLOWS {
                return;
            }
        }
        self.globals.packets_accepted += 1;
        self.globals.bytes_total += bytes;
        let dir = if local_addrs.is_empty() {
            Direction::Unknown
        } else if local_addrs.contains(&src) {
            Direction::Sent
        } else if local_addrs.contains(&dst) {
            Direction::Received
        } else {
            Direction::Unknown
        };
        match dir {
            Direction::Sent => self.globals.bytes_sent += bytes,
            Direction::Received => self.globals.bytes_recv += bytes,
            Direction::Unknown => {}
        }
        let entry = self
            .flows
            .entry(key.clone())
            .or_insert_with(|| FlowStats::new(key, now));
        entry.record_endpoints(now, src, sport, bytes);
        entry.record(now, bytes, dir, tcp);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_filtered(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
        protocol: u8,
        bytes: u64,
        local_addrs: &[IpAddr],
        now: Instant,
        filter: &PacketFilter,
        tcp: Option<TcpFlags>,
    ) -> bool {
        if filter.net4.is_some() || filter.net6.is_some() || !filter.allow_link_local {
            match filter.accept(src, dst) {
                None => {
                    self.globals.packets_seen += 1;
                    return false;
                }
                Some(sent) if filter.has_net_filter(src) => {
                    self.globals.packets_seen += 1;
                    let key = FlowKey::aggregate(
                        src,
                        dst,
                        sport,
                        dport,
                        protocol,
                        self.aggregate,
                        self.show_ports,
                    );
                    if !self.flows.contains_key(&key) && self.flows.len() >= MAX_FLOWS {
                        self.expire(now, Duration::from_secs(30));
                        if self.flows.len() >= MAX_FLOWS {
                            return true;
                        }
                    }
                    self.globals.packets_accepted += 1;
                    self.globals.bytes_total += bytes;
                    let dir = if sent {
                        Direction::Sent
                    } else {
                        Direction::Received
                    };
                    match dir {
                        Direction::Sent => self.globals.bytes_sent += bytes,
                        Direction::Received => self.globals.bytes_recv += bytes,
                        Direction::Unknown => {}
                    }
                    let entry = self
                        .flows
                        .entry(key.clone())
                        .or_insert_with(|| FlowStats::new(key, now));
                    entry.record_endpoints(now, src, sport, bytes);
                    entry.record(now, bytes, dir, tcp);
                    return true;
                }
                Some(_) => {}
            }
        }
        self.record(
            src,
            dst,
            sport,
            dport,
            protocol,
            bytes,
            local_addrs,
            now,
            tcp,
        );
        true
    }

    pub fn top(&self, n: usize, now: Instant) -> Vec<&FlowStats> {
        self.top_sorted(n, now, SortBy::Rate2s)
    }

    pub fn top_sorted(&self, n: usize, now: Instant, sort: SortBy) -> Vec<&FlowStats> {
        let mut list: Vec<&FlowStats> = self.flows.values().collect();
        list.sort_by(|a, b| match sort {
            SortBy::Rate2s => rate_ord(a.rate_2s(now), b.rate_2s(now)),
            SortBy::Rate10s => rate_ord(a.rate_10s(now), b.rate_10s(now)),
            SortBy::Rate40s => rate_ord(a.rate_40s(now), b.rate_40s(now)),
            SortBy::Total => b.total_bytes.cmp(&a.total_bytes),
            SortBy::Source => a.key.a.cmp(&b.key.a),
            SortBy::Destination => a.key.b.cmp(&b.key.b),
        });
        list.into_iter().take(n).collect()
    }

    pub fn snapshot(&self, n: usize, now: Instant) -> Snapshot {
        self.snapshot_sorted(n, now, SortBy::Rate2s)
    }

    pub fn snapshot_sorted(&self, n: usize, now: Instant, sort: SortBy) -> Snapshot {
        Snapshot {
            flows: self.top_sorted(n, now, sort).into_iter().cloned().collect(),
            globals: self.globals.clone(),
            taken_at: now,
        }
    }

    pub fn expire(&mut self, now: Instant, max_idle: Duration) {
        self.flows
            .retain(|_, s| now.duration_since(s.last_seen) < max_idle);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.flows.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}
