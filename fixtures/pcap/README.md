# PCAP fixtures

Deterministic packet captures for regression tests. **Do not** rely on live traffic.

## `r1_r4_flows.pcap`

| # | Direction (local=10.0.0.1) | IP len | Notes |
|---|---------------------------|--------|-------|
| 5 | 10.0.0.1 → 10.0.0.2 TCP | 100 | outgoing |
| 3 | 10.0.0.2 → 10.0.0.1 TCP | 200 | incoming |
| 1 | non-IP (ethertype ARP) | — | must be ignored |

Expected totals with `local=[10.0.0.1]`:
- `sent_bytes = 500`
- `recv_bytes = 600`
- `total_bytes = 1100`
- single flow key (R2)

Embedded as `tests/fixtures_data.rs` for CI without binary commits.
Regenerate: `python3 scripts/gen_fixture_r1_r4.py`

Regressions: **R1**, **R4**, **R2**, **R6** in `tests/regression_r1_r4.rs`.
