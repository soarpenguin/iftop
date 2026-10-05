use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::capture::pcap_file::open_pcap_file;
use crate::error::{Error, Result};
use crate::filters::{bpf_expression, PacketFilter};
use crate::flow::{Aggregate, FlowTable};
use crate::protocols::{decode_frame, DecodeResult};

pub fn process_pcap_file(
    path: impl AsRef<std::path::Path>,
    local_addrs: &[IpAddr],
) -> Result<FlowTable> {
    process_pcap_file_filtered(
        path,
        local_addrs,
        &PacketFilter::default(),
        Aggregate::Pair,
        false,
        None,
    )
}

pub fn process_pcap_file_filtered(
    path: impl AsRef<std::path::Path>,
    local_addrs: &[IpAddr],
    packet_filter: &PacketFilter,
    aggregate: Aggregate,
    show_ports: bool,
    bpf_filter: Option<&str>,
) -> Result<FlowTable> {
    let mut cap = open_pcap_file(path)?;
    if let Some(f) = bpf_filter {
        if !f.trim().is_empty() {
            cap.filter(&bpf_expression(Some(f)), true)?;
        }
    }
    let linktype = cap.get_datalink().0;
    let mut table = FlowTable::new();
    table.set_aggregate(aggregate);
    table.set_show_ports(show_ports);
    let base_instant = Instant::now();
    let mut first_ts: Option<Duration> = None;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                #[allow(clippy::cast_sign_loss)]
                let pkt_sec = packet.header.ts.tv_sec as u64;
                #[allow(clippy::cast_sign_loss)]
                let pkt_usec = packet.header.ts.tv_usec as u64;
                let pkt_ts = Duration::from_secs(pkt_sec) + Duration::from_micros(pkt_usec);

                let first = *first_ts.get_or_insert(pkt_ts);
                let elapsed_in_pcap = pkt_ts.saturating_sub(first);
                let when = base_instant + elapsed_in_pcap;

                if let DecodeResult::Ip(ep) = decode_frame(linktype, packet.data) {
                    table.record_filtered(
                        ep.src,
                        ep.dst,
                        ep.src_port,
                        ep.dst_port,
                        ep.protocol,
                        ep.ip_len,
                        local_addrs,
                        when,
                        packet_filter,
                        ep.tcp,
                    );
                }
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => return Err(Error::Pcap(e)),
        }
    }
    Ok(table)
}
