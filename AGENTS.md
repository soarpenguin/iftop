# AGENTS.md — Riftop Multi-Agent Operating Contract

## 1. Identity & Pure Safe Rust Requirement
`Riftop` is a real-time network bandwidth monitor (`iftop` rewrite) implemented exclusively in safe Rust (`unsafe_code = "forbid"`).
All new features, bug fixes, tooling, and scripts MUST be written in idiomatic, stable Rust.

---

## 2. Mandatory Policy: Truth, Accuracy & Trust
- **Truth & Accuracy**: Honesty, accuracy, and factual correctness are strictly mandatory. Lying, fabricating test results, or hallucinating invalidates agent work.
- **Stability & Trust**: Deterministic tests, uncompromised safety, and verifiable evidence mean survival and trust for autonomous coding agents.

---

## 3. Multi-Agent Operating Contract & Workflow
All autonomous agents (Jules, Codex, Claude Code, Gemini CLI, Copilot, Cursor, Cline, Amazon Q, Windsurf, Qwen, Kimi, Trae, Lingma) MUST follow this workflow:
1. **Inspect**: Examine project architecture (`docs/`) and code before proposing edits.
2. **Plan**: Formulate a targeted, minimal change plan.
3. **Reproduce**: Add or improve a failing regression test for any defect.
4. **Implement**: Apply the smallest correct fix in safe Rust.
5. **Validate**: Run tests, linters, and quality gates.
6. **Self-Review**: Inspect `git diff` for unintended changes or deletions.

---

## 4. Mandatory Non-Destructive Rules
- **No Unjustified Deletions**: Never delete healthy production code, tests, or fixtures.
- **No Weakened Assertions**: Never replace exact assertions with generic checks (`is_some()`, `is_finite()`, `> 0`).
- **No Whole-File Rewrites**: Apply localized edits rather than replacing entire modules.
- **No Dependency Drift**: Keep `Cargo.toml` and `Cargo.lock` strictly synchronized.

---

## 5. Verification Loop Commands
Execute these commands locally before completing tasks:
```bash
bash scripts/setup-environment.sh
LIBRARY_PATH=/app/target/lib:/usr/lib/x86_64-linux-gnu cargo fmt --all -- --check
LIBRARY_PATH=/app/target/lib:/usr/lib/x86_64-linux-gnu cargo check --all-targets --all-features
LIBRARY_PATH=/app/target/lib:/usr/lib/x86_64-linux-gnu cargo test --all-targets --all-features
LIBRARY_PATH=/app/target/lib:/usr/lib/x86_64-linux-gnu cargo clippy --all-targets --all-features -- -D warnings
```

---

## 6. System of Record & Architecture Map
Detailed project specifications reside in repository-local documentation:
- **Architecture & Invariants**: `docs/AI-DEVELOPMENT-GUIDE.md` & `docs/architecture.md`
- **Testing & Matrix**: `docs/testing-strategy.md` & `docs/test-matrix.md`
- **Roadmap & Tasks**: `docs/roadmap.md`
- **Environment & Scripts**: `scripts/setup-environment.sh` & `scripts/validate-agent-change.sh`
