# Legacy Riftop / iftop — architecture and behavior

Source: original C codebase in this repository (Paul Warren / Chris Lightfoot, iftop lineage).

## Purpose

Display real-time bandwidth usage on a network interface, ranked by host pairs (source ↔ destination), with sliding-window averages.

## Process model

- **Main thread**: curses UI (`ui.c`), tick-driven redraw.
- **Capture path**: libpcap callback (`packet_handler`) invoked from the pcap loop.
- **Resolver thread**: reverse DNS (`resolver.c`) via hash of pending lookups.
- Synchronization: `tick_mutex` around history rotation and UI print.

## Capture

- Opens device with libpcap, snaplen `CAPTURE_LENGTH` (256).
- Default BPF: `ip or ip6` (user filter AND-ed in).
- Multiple DLT handlers: Ethernet, Linux SLL, PPP, PFLOG, NULL, Token Ring, radiotap.
- Hardware direction from MAC (or SLL packet type); fallback to local IP match; else arbitrary ordering in promiscuous mode.

## Flow key (`addr_pair`)

- Address family (IPv4 / IPv6).
- Source and destination addresses (embedded in `in6_addr` for both).
- Source/destination ports when TCP/UDP.
- Protocol number.

Pairs are canonicalized so A↔B is unique (flip based on direction / numerical order).

## History / rates

- Circular buffer of length `HISTORY_LENGTH` (typically 40 slots).
- Resolution: 1 second (`RESOLUTION`).
- Display divisions: **2s, 10s, 40s** → `history_divs = {1, 5, 20}` (multiples of RESOLUTION).
- Per-flow: `sent[]`, `recv[]`, `total_sent`, `total_recv`.
- Totals: global `history_totals`.
- On tick: `analyse_data()` → aggregate into screen hash → sort → `ui_print()`.
- Expired flows: deleted when not written in current history position after rotation.

## Direction accounting

- **Outgoing**: MAC source = interface MAC, or IP source = interface IP.
- **Incoming**: MAC dest = interface MAC / broadcast, or IP dest = interface IP.
- Netfilter mode: direction by whether src/dst falls inside configured network.

## Byte counting

- IPv4: `ntohs(ip_len)` (total IP packet length).
- IPv6: `ntohs(ip6_plen) + 40`.

## UI (curses)

- Columns: host pair + three rate columns (2s / 10s / 40s) + optional totals.
- Sort by column 1/2/3, source name, dest name.
- Toggles: DNS (`n`), ports (`p`/`N`/`S`/`D`), bars (`b`), pause (`P`), help (`h`).
- Rate display: bits by default (`readable_size` with ×8), SI-ish scaling (1000 for display units in some paths, 1024 in others — **legacy inconsistency documented in compatibility.md**).

## Options (high level)

- Interface, BPF filter, promiscuous, net filter, DNS on/off, ports, bandwidth-in-bytes, bar scale, aggregate src/dest.

## Behaviors we must preserve (regression targets)

| ID | Behavior |
|----|----------|
| R1 | Rate windows approximate 2s / 10s / 40s averages |
| R2 | Flow key is bidirectional (A↔B unique) |
| R3 | TCP/UDP ports included when port display enabled |
| R4 | Direction based on local interface address when known |
| R5 | BPF filter applied; default includes IP/IPv6 only |
| R6 | Unsupported frames skipped without crash |
| R7 | Bandwidth shown in bits/s by default |
| R8 | Reverse DNS optional and non-blocking |

## Explicit non-goals for first Rust MVP

- Token Ring / radiotap / full PPP edge cases (can stub with graceful ignore).
- Bar graph log scale parity.
- Config file (`cfgfile`) parity (CLI first).
