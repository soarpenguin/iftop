# Phases 1–3 complete

## Phase 1 — Compatibility with iftop

| Feature | Implementation |
|---------|----------------|
| libpcap live capture | `capture::open_device` |
| Offline PCAP + same TUI | `--pcap` |
| IPv4 / IPv6 | `IpAddr` throughout |
| Rates 2s / 10s / 40s | `RateWindow` |
| BPF filter | `-f` + `bpf_expression` |
| Net filter v4/v6 | `-F` / `-G` |
| Link-local gate | `-l` |
| Screen filter | `--screen-filter` |
| Ports / DNS | `-P` / `-n` |
| Aggregation pair/src/dst | `--aggregate`, keys `a`/`s`/`d` |
| CAPTURED vs VISIBLE | header globals |
| Non-root capture | `setcap` + `privileges.rs` |

## Phase 2 — Modernization

| Feature | Implementation |
|---------|----------------|
| Snapshot for TUI | `FlowTable::snapshot` |
| Bounded channel | `engine.rs` + DROP counter |
| JSON / text / CSV | `--output` |
| TOML config | `config.rs`, `riftop.toml.example` |
| Interface kinds | `interfaces.rs` (eth/vlan/bond/br/wifi/virt) |
| Netns awareness | list + current ns id; enter via `ip netns exec` |
| `--list-interfaces` | CLI |

## Phase 3 — Troubleshooting

| Feature | Implementation |
|---------|----------------|
| TOP hosts/ports/protocols | keys 1–4 / Tab |
| TCP SYN/FIN/RST/ACK | `TcpCounters` |
| Retrans heuristic | seq repeat with payload |
| Connection duration | `first_seen` → `last_seen` |
| Rate / PPS alerts | `--alert-rate-bps`, `--alert-pps` |

## Explicitly out of scope (Phase 4+)

- Prometheus / HTTP API
- Full TCP RTT state machine
- Container cgroup labels without host integration
- DPI / IDS
