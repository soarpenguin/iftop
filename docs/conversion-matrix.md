# Conversion matrix: legacy C → Rust (Phases 1–3)

| Legacy module | Role | Rust status | Location |
|---------------|------|-------------|----------|
| `iftop.c` | main, capture loop | **Done** | `main.rs`, `capture/`, `engine.rs` |
| `ui.c` | rates, hotkeys, bars | **Done** | `ui/` |
| `options.c` | CLI flags | **Done** | `cli.rs` |
| `cfgfile.c` | config | **Done** | `config.rs` + TOML |
| `resolver.c` | reverse DNS | **Done** | `dns/` |
| `addr_hash` / `hash` | flow table | **Done** | `flow/` |
| `sorted_list.c` | sort | **Done** | `flow::top_sorted` / `SortBy` |
| `serv_hash.c` | port names | **Done** | `services.rs` (`-N` disables) |
| `screenfilter.c` | display filter | **Done** | `filters::ScreenFilter` + key `L` |
| `edline.c` | interactive filter | **Done** | key `L` prompts substring |
| `addrs_ioctl` | local IPs | **Done** | `capture::local_addresses` |
| ether/ip/tcp/sll | decode | **Done** | `protocols/` + real DLT |

## Feature parity

| Feature | Legacy | Rust |
|---------|--------|------|
| Live capture | ✓ | ✓ real datalink |
| Offline PCAP | — | ✓ `--pcap` |
| BPF | ✓ | ✓ |
| Rates 2s/10s/40s | ✓ | ✓ |
| Sort by column | ✓ | ✓ `--sort` / keys |
| Bits/bytes | ✓ | ✓ `-B` / key `B` |
| Bar graph | ✓ | ✓ default on; `-b` off; key `b` |
| Pause | ✓ | ✓ key `Space` |
| Ports + services | ✓ | ✓ `-P`; `-N` no service names |
| Net filter -F/-G | ✓ | ✓ accounting |
| Screen filter | ✓ | ✓ CLI + interactive `L` |
| Config file | ✓ | ✓ TOML |
| TOP views | partial | ✓ hosts/ports/proto |
| TCP flags / retrans | — | ✓ |
| Duration | — | ✓ column |
| CAPTURED vs VISIBLE | confusing | ✓ explicit |
