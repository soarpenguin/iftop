#!/usr/bin/env bash
set -euo pipefail

BASE="${1:-origin/master}"

echo "== Riftop Agent Validation Guardrail =="

# Check if git repository
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Not inside a git repository, skipping git diff check."
    exit 0
fi

# Check for deleted files relative to BASE or HEAD if BASE does not exist
if git rev-parse --verify "$BASE" >/dev/null 2>&1; then
    TARGET="$BASE...HEAD"
else
    TARGET="HEAD~1...HEAD"
fi

echo "Checking for unauthorized file deletions against $TARGET..."

deleted="$(git diff --name-status $TARGET 2>/dev/null | awk '$1 == "D" {print $2}' || true)"

if [[ -n "$deleted" ]]; then
    echo "ERROR: File deletion detected:"
    echo "$deleted"
    echo
    echo "File deletion requires explicit justification and human approval according to AGENTS.md."
    exit 1
fi

echo "✓ No unauthorized file deletions detected."
