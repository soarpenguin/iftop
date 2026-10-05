#!/usr/bin/env bash

set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
export CARGO_TERM_COLOR=always
export RUST_BACKTRACE=1

PROJECT_DIR="${1:-/app}"

echo "============================================================"
echo " Riftop - Multi-Agent Environment Setup"
echo "============================================================"

if [ -d "${PROJECT_DIR}" ]; then
    cd "${PROJECT_DIR}"
fi

echo
echo "[1/8] Repository validation"

if [ ! -f "Cargo.toml" ]; then
    echo "⚠️ Cargo.toml not found in current directory. Searching..."
    SUBDIR=$(find . -maxdepth 2 -name "Cargo.toml" -exec dirname {} \; | head -n 1)
    if [ -n "${SUBDIR}" ]; then
        echo "📁 Cargo.toml detected in ${SUBDIR}. Changing directory..."
        cd "${SUBDIR}"
    fi
fi

test -f Cargo.toml || {
    echo "ERROR: Cargo.toml not found in $(pwd)"
    exit 1
}

echo "Repository: $(pwd)"
echo "Branch: $(git branch --show-current 2>/dev/null || echo unknown)"
echo "Commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

echo
echo "[2/8] Environment Diagnostics"

echo "OS:"
grep PRETTY_NAME /etc/os-release || true

echo
echo "Rust & Tools:"
rustc --version
cargo --version
git --version

echo
echo "[3/8] Verify Native Dependencies (libpcap-dev, pkg-config)"

if command -v apt-get >/dev/null 2>&1; then
    if [[ "${EUID}" -eq 0 ]]; then
        APT="apt-get"
    elif command -v sudo >/dev/null 2>&1; then
        APT="sudo apt-get"
    else
        APT=""
    fi

    if [[ -n "${APT}" ]]; then
        ${APT} update
        ${APT} install -y --no-install-recommends libpcap-dev pkg-config
    fi
fi

# Linker fallback for container environments
if [ -f /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 ] && [ ! -f /usr/lib/x86_64-linux-gnu/libpcap.so ]; then
    ln -s /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 /usr/lib/x86_64-linux-gnu/libpcap.so 2>/dev/null || true
fi

echo
echo "[4/8] Validate libpcap"

if pkg-config --exists libpcap 2>/dev/null; then
    echo "libpcap version: $(pkg-config --modversion libpcap)"
fi

echo
echo "[5/8] Resolve locked dependencies"

if [[ -f Cargo.lock ]]; then
    cargo fetch --locked || cargo fetch
else
    cargo fetch
fi

echo
echo "[6/8] Check code compilation"

LIBRARY_PATH=/app/target/lib:/usr/lib/x86_64-linux-gnu cargo check --all-targets --all-features

echo
echo "[7/8] Compile test binaries"

LIBRARY_PATH=/app/target/lib:/usr/lib/x86_64-linux-gnu cargo test --no-run --all-targets --all-features

echo
echo "[8/8] Execute test suite"

LIBRARY_PATH=/app/target/lib:/usr/lib/x86_64-linux-gnu cargo test --all-targets --all-features

echo
echo "============================================================"
echo " RIFTOP ENVIRONMENT: READY & VERIFIED"
echo "============================================================"
