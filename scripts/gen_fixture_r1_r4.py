#!/usr/bin/env python3
"""Regenerate fixtures/pcap/r1_r4_flows.pcap"""
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "fixtures/pcap/r1_r4_flows.pcap"

gh = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

def eth_ipv4_tcp(src_ip, dst_ip, sport, dport, ip_total_len):
    src_mac = b"\x02\x00\x00\x00\x00\x01"
    dst_mac = b"\x02\x00\x00\x00\x00\x02"
    eth = dst_mac + src_mac + b"\x08\x00"
    src = bytes(int(x) for x in src_ip.split("."))
    dst = bytes(int(x) for x in dst_ip.split("."))
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, 0x1234, 0x4000, 64, 6, 0, src, dst,
    )
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, (5 << 4), 0x18, 8192, 0, 0)
    payload = b"\x00" * max(0, ip_total_len - 40)
    return eth + ip_hdr + tcp + payload

def rec(ts_sec, frame):
    return struct.pack("<IIII", ts_sec, 0, len(frame), len(frame)) + frame

records = b""
for i in range(5):
    records += rec(1_700_000_000 + i, eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 40000, 80, 100))
for i in range(3):
    records += rec(1_700_000_010 + i, eth_ipv4_tcp("10.0.0.2", "10.0.0.1", 80, 40000, 200))
garbage = b"\xff" * 6 + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x06" + b"\x00" * 28
records += rec(1_700_000_020, garbage)

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_bytes(gh + records)
print(f"Wrote {OUT} ({OUT.stat().st_size} bytes)")
