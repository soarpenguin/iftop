#!/usr/bin/env bash
# Offline regression suite — no root required.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> fmt"
cargo fmt --all -- --check

echo "==> clippy"
cargo clippy --all-targets --all-features -- -D warnings

echo "==> test"
cargo test --all-features

if command -v cargo-nextest >/dev/null 2>&1; then
  echo "==> nextest"
  cargo nextest run --all-features
fi

if command -v cargo-audit >/dev/null 2>&1; then
  echo "==> audit"
  cargo audit || true
fi

echo "==> regression OK"
