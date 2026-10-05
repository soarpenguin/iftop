use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::flow::key::FlowKey;
use crate::flow::rate::RateWindow;
use crate::protocols::TcpFlags;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Sent,
    Received,
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct TcpCounters {
    pub syn: u64,
    pub fin: u64,
    pub rst: u64,
    pub pure_ack: u64,
    pub retrans: u64,
    last_data_seq: Option<u32>,
}

impl TcpCounters {
    pub fn observe(&mut self, flags: TcpFlags) {
        if flags.syn {
            self.syn += 1;
        }
        if flags.fin {
            self.fin += 1;
        }
        if flags.rst {
            self.rst += 1;
        }
        if flags.pure_ack {
            self.pure_ack += 1;
        }
        if flags.payload_len > 0 {
            if self.last_data_seq == Some(flags.seq) {
                self.retrans += 1;
            }
            self.last_data_seq = Some(flags.seq);
        }
    }

    #[must_use]
    pub fn summary(&self) -> String {
        if self.syn == 0
            && self.fin == 0
            && self.rst == 0
            && self.pure_ack == 0
            && self.retrans == 0
        {
            return String::new();
        }
        format!(
            "S{} F{} R{} A{} X{}",
            self.syn, self.fin, self.rst, self.pure_ack, self.retrans
        )
    }
}

#[derive(Debug, Clone)]
pub struct FlowStats {
    pub key: FlowKey,
    pub total_bytes: u64,
    pub sent_bytes: u64,
    pub recv_bytes: u64,
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
    pub packets: u64,
    pub tcp: TcpCounters,
    pub rate_2s: RateWindow,
    pub rate_10s: RateWindow,
    pub rate_40s: RateWindow,
    pub rate_a_to_b_2s: RateWindow,
    pub rate_a_to_b_10s: RateWindow,
    pub rate_a_to_b_40s: RateWindow,
    pub rate_b_to_a_2s: RateWindow,
    pub rate_b_to_a_10s: RateWindow,
    pub rate_b_to_a_40s: RateWindow,
    pub first_seen: Instant,
    pub last_seen: Instant,
}

impl FlowStats {
    #[must_use]
    pub fn new(key: FlowKey, now: Instant) -> Self {
        Self {
            key,
            total_bytes: 0,
            sent_bytes: 0,
            recv_bytes: 0,
            bytes_a_to_b: 0,
            bytes_b_to_a: 0,
            packets: 0,
            tcp: TcpCounters::default(),
            rate_2s: RateWindow::new(Duration::from_secs(2)),
            rate_10s: RateWindow::new(Duration::from_secs(10)),
            rate_40s: RateWindow::new(Duration::from_secs(40)),
            rate_a_to_b_2s: RateWindow::new(Duration::from_secs(2)),
            rate_a_to_b_10s: RateWindow::new(Duration::from_secs(10)),
            rate_a_to_b_40s: RateWindow::new(Duration::from_secs(40)),
            rate_b_to_a_2s: RateWindow::new(Duration::from_secs(2)),
            rate_b_to_a_10s: RateWindow::new(Duration::from_secs(10)),
            rate_b_to_a_40s: RateWindow::new(Duration::from_secs(40)),
            first_seen: now,
            last_seen: now,
        }
    }

    pub fn record_endpoints(&mut self, now: Instant, src: IpAddr, sport: u16, bytes: u64) {
        let is_a = if self.key.port_a != 0 {
            (src, sport) == (self.key.a, self.key.port_a)
        } else {
            src == self.key.a
        };
        if is_a {
            self.bytes_a_to_b += bytes;
            self.rate_a_to_b_2s.add(now, bytes);
            self.rate_a_to_b_10s.add(now, bytes);
            self.rate_a_to_b_40s.add(now, bytes);
        } else {
            self.bytes_b_to_a += bytes;
            self.rate_b_to_a_2s.add(now, bytes);
            self.rate_b_to_a_10s.add(now, bytes);
            self.rate_b_to_a_40s.add(now, bytes);
        }
    }

    pub fn record(&mut self, now: Instant, bytes: u64, dir: Direction, tcp: Option<TcpFlags>) {
        self.total_bytes += bytes;
        self.packets += 1;
        match dir {
            Direction::Sent => self.sent_bytes += bytes,
            Direction::Received => self.recv_bytes += bytes,
            Direction::Unknown => {}
        }
        if let Some(f) = tcp {
            self.tcp.observe(f);
        }
        self.rate_2s.add(now, bytes);
        self.rate_10s.add(now, bytes);
        self.rate_40s.add(now, bytes);
        self.last_seen = now;
    }

    #[must_use]
    pub fn duration(&self) -> Duration {
        self.last_seen.saturating_duration_since(self.first_seen)
    }

    pub fn rate_2s(&self, now: Instant) -> f64 {
        self.rate_2s.rate(now)
    }
    pub fn rate_10s(&self, now: Instant) -> f64 {
        self.rate_10s.rate(now)
    }
    pub fn rate_40s(&self, now: Instant) -> f64 {
        self.rate_40s.rate(now)
    }
}
