# Riftop Test Coverage Matrix

| Area | Test Type | Test Count | Fixture / Input | Root Required | Deterministic | CI Enabled |
| :--- | :-------- | :--------- | :-------------- | :------------ | :------------ | :--------- |
| Build / Core / API | Unit / Integration | 5 | In-memory structs | No | Yes | Yes |
| Configuration / CLI | Integration | 5 | Temp TOML & CLI args | No | Yes | Yes |
| Packet Decoding | Unit | 8 | Synthetic frame bytes | No | Yes | Yes |
| Link Types / DLTs | Unit | 5 | Synthetic link frames | No | Yes | Yes |
| PCAP Replay & Filters | Integration | 5 | PCAP files & BPF | No | Yes | Yes |
| Flow Tracking & Direction | Integration | 6 | FlowKeys & FlowTable | No | Yes | Yes |
| Limits & Safety | Stress | 3 | High flow counts | No | Yes | Yes |
| Rate Calculations | Unit | 3 | RateWindow timelines | No | Yes | Yes |
| Top Statistics | Integration | 3 | Snapshot statistics | No | Yes | Yes |
| Export Formats | Integration | 3 | JSON/CSV/Text writers | No | Yes | Yes |
| DNS Cache & Concurrency | Integration | 2 | DnsCache & Arc | No | Yes | Yes |
| End-to-End Pipelines | E2E | 2 | Live & PCAP pipelines | No | Yes | Yes |
| **Total** | **All Types** | **50** | **Comprehensive Suite** | **No** | **Yes** | **Yes** |
