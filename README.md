# Riftop

Modern **iftop**-style real-time bandwidth monitor written in Rust.

Branch: [`refactorc_testing`](https://github.com/jperez1250/Riftop/tree/refactorc_testing) — **Phases 1–3 complete**. See [docs/roadmap.md](docs/roadmap.md) and [docs/phase1-3-complete.md](docs/phase1-3-complete.md).

## Features (Phases 1–3)

- Live capture (libpcap) + offline PCAP with the **same TUI**
- IPv4/IPv6, rates 2s/10s/40s, aggregation pair/src/dst
- BPF, net-filter (`-F`/`-G`), link-local, screen filter
- CAPTURED vs VISIBLE totals, bounded capture→engine channel
- TOP hosts / ports / protocols (keys `1`–`4`)
- TCP flags + retransmit heuristic + flow duration
- Rate / PPS alerts, JSON/CSV/text export, TOML config
- Interface kinds (eth/vlan/bond/bridge/wifi) + netns listing

## Build

```bash
# Needs: libpcap-dev, Rust stable
cargo build --release

# Non-root capture (recommended)
sudo setcap cap_net_raw,cap_net_admin=eip target/release/riftop
```

## Usage

```bash
# Live
./target/release/riftop -i eth0
./target/release/riftop -f "tcp port 443" --aggregate src

# List interfaces + netns
./target/release/riftop --list-interfaces

# Inside a network namespace
sudo ip netns exec myns ./target/release/riftop -i eth0

# Offline PCAP (no root)
./target/release/riftop --pcap capture.pcap
./target/release/riftop --pcap capture.pcap --output json

# Alerts
./target/release/riftop -i eth0 --alert-rate-bps 125000000 --alert-pps 50000

# Config file
cp riftop.toml.example riftop.toml
./target/release/riftop --config ./riftop.toml
```

## TUI keys

| Key | Action |
|-----|--------|
| `q` | Quit |
| `1`–`4` | Flows / Hosts / Ports / Protocols |
| `Tab` | Cycle views |
| `p` | Toggle ports |
| `n` | Toggle DNS |
| `a`/`s`/`d` | Aggregate pair / source / destination |

TCP column: `S` SYN · `F` FIN · `R` RST · `A` pure-ACK · `X` retrans heuristic

## Tests

```bash
cargo test
# or
./scripts/test-regression.sh
```

## Layout

```
src/
  capture/   live + offline PCAP
  protocols/ Ethernet/VLAN/QinQ/IP/TCP/UDP
  flow/      rates, TCP counters, aggregation
  engine/    bounded channel + backpressure
  filters/   BPF helpers, net-filter, screen
  interfaces/ kind + netns discovery
  config/    TOML
  alerts/    rate/PPS
  top/       hosts/ports/protocols views
  ui/        ratatui
docs/
tests/regression_*.rs
```

## License

GPL-2.0-or-later (same spirit as original iftop).
