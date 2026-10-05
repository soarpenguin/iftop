# Riftop Automated Testing Strategy

## Overview
This document outlines the testing architecture, quality gates, and automated test coverage for `riftop`.

---

## Test Categories

1. **Build & Core API Integration (Tests 01–05)**
   - Debug and release build verification
   - Formatting and strict clippy lint checks
   - Library and binary crate interface alignment

2. **Configuration & CLI (Tests 06–10)**
   - TOML config parsing and invalid input rejection
   - CLI option precedence over configuration file defaults
   - Behavioral verification of `--sort`, `-B`/`--bytes`, `-b`/`--no-bars`, `-N`/`--no-port-resolution`

3. **Packet Decoding (Tests 11–18)**
   - Ethernet + IPv4 + TCP/UDP/ICMP
   - Ethernet + IPv6 + TCP/UDP
   - IPv6 Extension Header traversal (Hop-by-Hop, Routing, Destination Options, Fragment)
   - VLAN 802.1Q and QinQ 802.1ad tagging

4. **Link Types & DLTs (Tests 19–23)**
   - DLT_EN10MB (Ethernet = 1)
   - DLT_RAW (12, 101)
   - DLT_LINUX_SLL (113) and DLT_NULL (0)
   - Unknown/unsupported DLT fallback

5. **PCAP Replay, Timestamps & Filtering (Tests 24–28)**
   - PCAP header timestamp extraction and relative timeline preservation
   - BPF capture filter compilation and execution
   - Live capture vs offline PCAP parity

6. **Flow Tracking & Direction (Tests 29–34)**
   - Single bidirectional flow key mapping
   - Sent vs Received directional byte accounting
   - Ephemeral vs Server port aggregation
   - Dual-stack IPv4/IPv6 flow co-existence

7. **Resource Safety & Limits (Tests 35–37)**
   - `MAX_FLOWS` capacity capping (100,000 entries)
   - Flow expiration pruning (`expire()`)
   - High-cardinality memory pressure resilience

8. **Rate Window Calculations (Tests 38–40)**
   - Fixed window duration evaluation (2s, 10s, 40s)
   - Underflow prevention (`checked_sub` and `checked_duration_since`)

9. **Top Statistics (Tests 41–43)**
   - Directional host traffic accounting (`sent_bytes` for source, `recv_bytes` for destination)
   - Top ports and top protocols aggregation

10. **Export & Output Coherence (Tests 44–46)**
    - Requested sort column propagation (`SortBy`)
    - Bits vs bytes rate unit formatting (`format_rate_units`)
    - Output format consistency across JSON, CSV, and Text

11. **DNS Cache & Concurrency (Tests 47–48)**
    - Cache hit verification and negative resolution preservation
    - Concurrent background lookup deduplication (`pending` set)

12. **End-to-End Pipelines (Tests 49–50)**
    - End-to-end Live pipeline (frame -> decode -> table -> snapshot -> json)
    - End-to-end PCAP file processing pipeline
