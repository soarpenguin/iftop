//! Packet decoding — no statistics, no I/O.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub pure_ack: bool,
    pub seq: u32,
    pub payload_len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEndpoints {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub ip_len: u64,
    pub tcp: Option<TcpFlags>,
    pub vlan_id: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeResult {
    Ip(FlowEndpoints),
    Ignored,
}

pub fn decode_frame(linktype: i32, frame: &[u8]) -> DecodeResult {
    match linktype {
        1 => decode_ethernet(frame),
        12 | 101 => decode_ip_payload(frame, None),
        113 => decode_linux_sll(frame),  // DLT_LINUX_SLL = 113
        276 => decode_linux_sll2(frame), // DLT_LINUX_SLL2 = 276
        0 => {
            if frame.len() > 4 {
                decode_ip_payload(&frame[4..], None)
            } else {
                DecodeResult::Ignored
            }
        }
        _ => DecodeResult::Ignored,
    }
}

pub fn decode_ethernet(frame: &[u8]) -> DecodeResult {
    if frame.len() < 14 {
        return DecodeResult::Ignored;
    }
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = 14usize;
    let mut vlan_id = None;

    // 802.1Q and QinQ (double tag)
    while ethertype == 0x8100 || ethertype == 0x88a8 {
        if frame.len() < offset + 4 {
            return DecodeResult::Ignored;
        }
        let tci = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
        vlan_id = Some(tci & 0x0fff);
        ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }

    if ethertype != 0x0800 && ethertype != 0x86DD {
        return DecodeResult::Ignored;
    }
    decode_ip_payload(&frame[offset..], vlan_id)
}

fn decode_linux_sll(frame: &[u8]) -> DecodeResult {
    if frame.len() < 16 {
        return DecodeResult::Ignored;
    }
    let protocol = u16::from_be_bytes([frame[14], frame[15]]);
    if protocol != 0x0800 && protocol != 0x86DD {
        return DecodeResult::Ignored;
    }
    decode_ip_payload(&frame[16..], None)
}

fn decode_linux_sll2(frame: &[u8]) -> DecodeResult {
    if frame.len() < 20 {
        return DecodeResult::Ignored;
    }
    let protocol = u16::from_be_bytes([frame[0], frame[1]]);
    if protocol != 0x0800 && protocol != 0x86DD {
        return DecodeResult::Ignored;
    }
    decode_ip_payload(&frame[20..], None)
}

fn decode_ip_payload(payload: &[u8], vlan_id: Option<u16>) -> DecodeResult {
    use etherparse::{LaxNetSlice, LaxSlicedPacket, TransportSlice};

    let sliced = match LaxSlicedPacket::from_ip(payload) {
        Ok(s) => s,
        Err(_) => return DecodeResult::Ignored,
    };

    let (src, dst, protocol, ip_len, incomplete) = match sliced.net {
        Some(LaxNetSlice::Ipv4(ref h)) => {
            let raw_len = u64::from(h.header().total_len());
            let hdr_len = h.header().slice().len() as u64;
            let ip_len = if raw_len < hdr_len {
                payload.len() as u64
            } else {
                raw_len
            };
            (
                IpAddr::V4(h.header().source_addr()),
                IpAddr::V4(h.header().destination_addr()),
                h.payload().ip_number.0,
                ip_len,
                h.payload().incomplete,
            )
        }
        Some(LaxNetSlice::Ipv6(ref h)) => {
            let payload_len = u64::from(h.header().payload_length());
            let ip_len = if payload_len == 0 {
                payload.len() as u64
            } else {
                payload_len + 40
            };
            (
                IpAddr::V6(h.header().source_addr()),
                IpAddr::V6(h.header().destination_addr()),
                h.payload().ip_number.0,
                ip_len,
                h.payload().incomplete,
            )
        }
        _ => return DecodeResult::Ignored,
    };

    let missing = if incomplete {
        ip_len.saturating_sub(payload.len() as u64)
    } else {
        0
    };

    let (src_port, dst_port, tcp) = match sliced.transport {
        Some(TransportSlice::Tcp(t)) => {
            let syn = t.syn();
            let ack = t.ack();
            let fin = t.fin();
            let rst = t.rst();
            let psh = t.psh();
            let payload_len = (t.payload().len() as u64 + missing).min(u64::from(u32::MAX)) as u32;
            let pure_ack = ack && !syn && !fin && !rst && payload_len == 0;
            (
                t.source_port(),
                t.destination_port(),
                Some(TcpFlags {
                    syn,
                    ack,
                    fin,
                    rst,
                    psh,
                    pure_ack,
                    seq: t.sequence_number(),
                    payload_len,
                }),
            )
        }
        Some(TransportSlice::Udp(u)) => (u.source_port(), u.destination_port(), None),
        _ => (0, 0, None),
    };

    DecodeResult::Ip(FlowEndpoints {
        src,
        dst,
        src_port,
        dst_port,
        protocol,
        ip_len,
        tcp,
        vlan_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_ignored() {
        assert_eq!(decode_ethernet(&[]), DecodeResult::Ignored);
        assert_eq!(decode_frame(1, &[]), DecodeResult::Ignored);
    }
}
