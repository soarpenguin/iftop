use std::net::IpAddr;
use std::thread;

use pcap::{Active, Capture, Device};

use crate::engine::EngineHandle;
use crate::error::{Error, Result};
use crate::filters::{bpf_expression, PacketFilter};
use crate::protocols::{decode_frame, DecodeResult};

pub fn open_device(name: Option<&str>, promiscuous: bool) -> Result<Capture<Active>> {
    let device = if let Some(n) = name {
        Device::list()?
            .into_iter()
            .find(|d| d.name == n)
            .ok_or_else(|| Error::InvalidInterface(n.to_string()))?
    } else {
        Device::list()?
            .into_iter()
            .find(|d| {
                !d.name.starts_with("lo")
                    && !d.name.starts_with("docker")
                    && !d.name.starts_with("veth")
                    && d.addresses
                        .iter()
                        .any(|a| matches!(a.addr, IpAddr::V4(_) | IpAddr::V6(_)))
            })
            .or_else(|| Device::lookup().ok().flatten())
            .ok_or(Error::NoInterface)?
    };

    Ok(Capture::from_device(device)?
        .promisc(promiscuous)
        .snaplen(65535)
        .timeout(250)
        .open()?)
}

pub fn set_filter(cap: &mut Capture<Active>, filter: Option<&str>) -> Result<()> {
    cap.filter(&bpf_expression(filter), true)?;
    Ok(())
}

#[must_use]
pub fn local_addresses(name: &str) -> Vec<IpAddr> {
    Device::list()
        .unwrap_or_default()
        .into_iter()
        .find(|d| d.name == name)
        .map(|d| d.addresses.into_iter().map(|a| a.addr).collect())
        .unwrap_or_default()
}

pub fn spawn_capture_to_engine(
    mut cap: Capture<Active>,
    engine: EngineHandle,
) -> thread::JoinHandle<()> {
    let linktype = cap.get_datalink().0;
    thread::spawn(move || loop {
        match cap.next_packet() {
            Ok(packet) => {
                let now = std::time::Instant::now();
                if let DecodeResult::Ip(ep) = decode_frame(linktype, packet.data) {
                    engine.try_send(crate::engine::PacketEvent {
                        src: ep.src,
                        dst: ep.dst,
                        sport: ep.src_port,
                        dport: ep.dst_port,
                        protocol: ep.protocol,
                        bytes: ep.ip_len,
                        when: now,
                        tcp: ep.tcp,
                    });
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => break,
        }
    })
}

pub fn spawn_capture_thread(
    mut cap: Capture<Active>,
    flows: crate::capture::SharedFlows,
    local_addrs: Vec<IpAddr>,
    packet_filter: PacketFilter,
) -> thread::JoinHandle<()> {
    let linktype = cap.get_datalink().0;
    thread::spawn(move || loop {
        match cap.next_packet() {
            Ok(packet) => {
                let now = std::time::Instant::now();
                if let DecodeResult::Ip(ep) = decode_frame(linktype, packet.data) {
                    flows.lock().record_filtered(
                        ep.src,
                        ep.dst,
                        ep.src_port,
                        ep.dst_port,
                        ep.protocol,
                        ep.ip_len,
                        &local_addrs,
                        now,
                        &packet_filter,
                        ep.tcp,
                    );
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => break,
        }
    })
}
