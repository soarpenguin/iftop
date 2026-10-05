# Riftop Multi-Agent Architectural & Engineering Guide

## Multi-Agent System Architecture

`Riftop` is designed as a multi-agent, agent-agnostic repository. It relies on a single canonical engineering contract in `AGENTS.md` and repository-local documentation under `docs/` rather than agent-specific prompt fragmentation.

Supported agents (Jules, Codex, Claude Code, Gemini CLI, Copilot, Cursor, Cline, Amazon Q, Windsurf, Qwen, Kimi, Trae, Lingma) observe the same domain invariants and quality gates.

---

## Domain Invariants & Technical Rules

1. **Pure Safe Rust**: All codebase components MUST be written in safe Rust (`unsafe_code = "forbid"`).
2. **Truth & Verification**: Test reports and claims MUST reflect actual executed results. Tautological assertions or silenced errors are forbidden.
3. **Flow Identity (`FlowKey`)**: 5-tuple `(a, b, port_a, port_b, protocol)` identity remains distinct regardless of `--ports`/`--no-ports` presentation options.
4. **Endpoint Rate & Byte Attribution**: Host and port rates/bytes are attributed directionally (`bytes_a_to_b` / `bytes_b_to_a`) to prevent double-counting flow totals.
5. **Capacity Protection**: `FlowTable` caps entries at `MAX_FLOWS = 100,000` before incrementing accepted statistics.
6. **Replay Clock & Locality**: Offline PCAP timestamps are relative to `pcap_start`, with `Direction::Unknown` when local interface IPs are unavailable.
