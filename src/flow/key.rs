use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Aggregate {
    #[default]
    Pair,
    Source,
    Destination,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub a: IpAddr,
    pub b: IpAddr,
    pub port_a: u16,
    pub port_b: u16,
    pub protocol: u8,
}

impl FlowKey {
    pub fn new(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, protocol: u8) -> Self {
        if (src, sport) <= (dst, dport) {
            Self {
                a: src,
                b: dst,
                port_a: sport,
                port_b: dport,
                protocol,
            }
        } else {
            Self {
                a: dst,
                b: src,
                port_a: dport,
                port_b: sport,
                protocol,
            }
        }
    }

    pub fn aggregate(
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
        protocol: u8,
        mode: Aggregate,
        show_ports: bool,
    ) -> Self {
        match mode {
            Aggregate::Source => Self {
                a: src,
                b: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                port_a: if show_ports { sport } else { 0 },
                port_b: 0,
                protocol: if show_ports { protocol } else { 0 },
            },
            Aggregate::Destination => Self {
                a: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                b: dst,
                port_a: 0,
                port_b: if show_ports { dport } else { 0 },
                protocol: if show_ports { protocol } else { 0 },
            },
            Aggregate::Pair if show_ports => Self::new(src, dst, sport, dport, protocol),
            Aggregate::Pair => Self::new(src, dst, 0, 0, 0),
        }
    }
}
