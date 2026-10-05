# Project rules — Riftop Rust rewrite

1. Do not rewrite Riftop blindly.
2. First analyze the legacy Riftop source code and document its architecture and behavior.
3. Preserve user-visible functionality unless there is a documented reason to change it.
4. Do not introduce architectural changes merely for stylistic reasons.
5. Prefer Rust-native abstractions, but preserve the observable behavior of the original application.
6. Use libpcap for packet capture.
7. Separate packet capture, packet decoding, statistics, application state and TUI rendering into independent modules.
8. Avoid coupling packet capture directly to the UI.
9. Every major legacy behavior that is ported should have a regression test.
10. PCAP files must be treated as deterministic test fixtures.
11. Do not use live network traffic for deterministic unit/regression tests.
12. Tests must be runnable without root privileges whenever possible.
13. Packet capture privileges must be isolated from the rest of the application.
14. Do not silently change protocol parsing semantics.
15. Unsupported protocols should fail gracefully rather than terminate the application.
16. Avoid unsafe Rust unless there is a demonstrated requirement.
17. Any unsafe code must include a clear safety justification.
18. Before considering a change complete, run:
    - `cargo fmt --check`
    - `cargo clippy --all-targets --all-features -- -D warnings`
    - `cargo test --all-features`
    - `cargo nextest run` (when available)
    - `cargo audit`
    - `cargo deny check`
19. Keep compatibility tests separate from implementation tests.
20. Document any intentional behavioral difference from legacy Riftop.

## Development order

```
legacy Riftop → behavior analysis → parser/capture → statistics → PCAP tests → comparison → TUI
```

Do not start with the TUI. Validate rates and flow accounting against fixtures first.
