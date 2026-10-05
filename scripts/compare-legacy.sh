#!/usr/bin/env bash
# Compare Rust offline accounting against a legacy iftop binary (optional).
# Usage: ./scripts/compare-legacy.sh fixtures/pcap/sample.pcap
set -euo pipefail
PCAP="${1:?usage: compare-legacy.sh <file.pcap>}"

echo "TODO: run legacy iftop in batch/offline mode if available"
echo "TODO: run: cargo run -- --pcap $PCAP --json"
echo "Fixture: $PCAP"
echo "Document differences in docs/compatibility.md"
