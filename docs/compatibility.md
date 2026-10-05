# Compatibility with legacy Riftop / iftop

## Intentional differences (documented)

| Topic | Legacy | Rust | Reason |
|-------|--------|------|--------|
| UI toolkit | ncurses | ratatui | maintainable TUI; same information density target |
| Config file | `~/.iftoprc` style | CLI-first; config later | simplify MVP |
| Unit scaling | mixed 1000/1024 paths | consistent policy (document in code) | avoid silent dual behavior |
| DLT coverage | many link types | Ethernet + Linux SLL first | expand with tests |

## Must-match behaviors

See regression IDs R1–R8 in `legacy-analysis.md`.

## How to verify

```bash
# Offline only (no root)
cargo test --all-features
./scripts/test-regression.sh

# Optional: compare against legacy binary if built
./scripts/compare-legacy.sh fixtures/pcap/sample.pcap
```

Any new intentional difference must be added to the table above in the same PR.
