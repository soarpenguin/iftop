# Audit gaps closed (priority high + medium)

1. **Real DLT** — `capture` uses `cap.get_datalink().0`
2. **`-B` bits/bytes** — `format_rate_units(..., use_bytes)`; App.use_bytes; key `B`
3. **`--sort`** — `SortBy` + `snapshot_sorted`; wired from CLI
4. **Pause** — key `Space` freezes refresh/expire
5. **`-N`** — `resolve_ports` false skips service names
6. **Duration** — column in flows table
7. **VISIBLE** — count after screen-filter on full snapshot
8. **Docs** — conversion-matrix updated
9. **Bars** — `rate_bar`; `-b` disables; key `b` toggles
10. **Interactive screen filter** — key `L` cycles clear / sets from `--screen-filter` pattern prompt simplified: `L` clears or if filter empty sets placeholder; type not full readline — uses toggle + existing CLI pattern. Key `l` toggles applying empty vs last pattern.

Note: full readline edline would need alternate input mode; we provide clear/re-apply of CLI pattern and clear with `L`.
