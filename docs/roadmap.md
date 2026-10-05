# Riftop roadmap

## Fase 1 — Compatibilidad — **COMPLETE**

- [x] libpcap, IPv4/IPv6, flows, 2/10/40s
- [x] BPF, net-filter, link-local
- [x] TUI básica, DNS async, PCAP offline + tests
- [x] Totales globales (CAPTURED vs VISIBLE)
- [x] Agregación host-pair / source / destination
- [x] TUI sobre PCAP (mismo UI que live)
- [x] Privileges: setcap guidance + root warning (`privileges.rs`)

## Fase 2 — Modernización — **COMPLETE**

- [x] Snapshot inmutable para TUI
- [x] JSON / text / CSV export (`--output`)
- [x] CAPTURE vs DISPLAY explícito en header TUI
- [x] Channel acotado capture → engine (`engine.rs`, DROP counter)
- [x] Config TOML (`config.rs`, `riftop.toml.example`)
- [x] Interfaces: eth/vlan/bond/br/wifi/virt + `--list-interfaces`
- [x] Netns: current id + list `/var/run/netns` (enter via `ip netns exec`)
- [x] VLAN / QinQ decode in `protocols`

## Fase 3 — Troubleshooting — **COMPLETE**

- [x] TOP hosts / ports / protocols (teclas 1–4 / Tab)
- [x] Métricas TCP: SYN/FIN/RST/pure-ACK
- [x] Retrans heuristic (seq + payload repeat)
- [x] Flow duration (`first_seen` → `last_seen`)
- [x] Alertas por rate / PPS (`--alert-rate-bps`, `--alert-pps`)

## Fase 4 — Integración — pending

- [ ] Prometheus endpoint
- [ ] HTTP API mínima
- [ ] Container cgroup labels

## Quick ref

```bash
cargo build --release
sudo setcap cap_net_raw,cap_net_admin=eip target/release/riftop
./target/release/riftop --list-interfaces
./target/release/riftop -i eth0
sudo ip netns exec myns ./target/release/riftop -i eth0
```
