# Network filters

## 1. BPF capture filter (`-f` / `--filter-code`)

Applied by libpcap **before** userspace sees packets.

```bash
riftop -f "tcp port 443"
riftop -f "host 8.8.8.8"
```

Always combined with `(ip or ip6)` (legacy iftop behaviour).

## 2. IPv4 net filter (`-F` / `--net-filter`)

Only count traffic that **crosses** the network boundary:

| src in net | dst in net | Action |
|------------|------------|--------|
| yes | no | count as **sent** (out) |
| no | yes | count as **recv** (in) |
| yes | yes | drop |
| no | no | drop |

```bash
riftop -F 10.0.0.0/24
riftop -F 192.168.1.0/255.255.255.0
```

## 3. IPv6 net filter (`-G` / `--net-filter6`)

Same logic for IPv6:

```bash
riftop -G 2001:db8::/32
riftop -G fe80::/10
```

## 4. Link-local IPv6 (`-l` / `--link-local`)

By default, packets with `fe80::/10` endpoints are **dropped**.

```bash
riftop -l   # include link-local
```

## 5. Screen filter (`--screen-filter`)

Display-only: hide rows whose host names do not contain the substring.

```bash
riftop --screen-filter google
```

Does not affect accounting.

## 6. Combinations

```bash
# Only HTTPS crossing the LAN boundary
sudo riftop -i eth0 -F 192.168.0.0/16 -f "tcp port 443"

# IPv6 only, include link-local
sudo riftop -G 2001:db8::/32 -l
```
