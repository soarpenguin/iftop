# Riftop Architecture & Domain Invariants

## Pipeline Architecture

```text
Capture (pcap / live)
   │
   ▼
PacketDecoder (Ethernet / SLL / SLL2 / RAW / IPv4 / IPv6 / TCP / UDP)
   │
   ▼
PacketEvent
   │
   ├─► BPF & Network Filters
   │
   ▼
FlowEngine (mpsc channel)
   │
   ▼
FlowTable (Capacity MAX_FLOWS = 100,000)
   │
   ├─► RateWindows (2s, 10s, 40s)
   ├─► Direction Accounting (Sent / Received / Unknown)
   └─► Global Counters (seen, accepted, total bytes, sent bytes, recv bytes)
   │
   ▼
Snapshot Engine
   │
   ├─► Top Hosts (directional bytes_a_to_b / bytes_b_to_a)
   ├─► Top Ports (directional port_a / port_b attribution)
   ├─► Top Protocols (independent of presentation flags)
   │
   ▼
TUI & Export (JSON with json_escape, CSV, Text)
```

## Domain Invariants

1. **Flow Identity (`FlowKey`) vs Presentation (`show_ports`)**
   - Flow identity is a 5-tuple `(a, b, port_a, port_b, protocol)`.
   - UI toggles like `--no-ports` MUST NOT mutate the underlying `FlowKey` protocol ID or merge distinct connections in `FlowTable`.

2. **Directional Accounting & Rates**
   - Directional byte counters (`bytes_a_to_b`, `bytes_b_to_a`) attribute traffic from `a` to `b` vs `b` to `a`.
   - Top Hosts and Top Ports attribute directional bytes and directional rates to prevent double-counting flow totals.

3. **PCAP Replay Clock & Direction**
   - Offline PCAP timestamps are computed relative to `pcap_start`.
   - Direction is classified as `Direction::Unknown` when local interface addresses are absent.

4. **Capacity Enforcement (`MAX_FLOWS = 100,000`)**
   - Flow admission is checked before incrementing accepted packet and total byte statistics.
