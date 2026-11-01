# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-01

### Added
- Five-step decision pipeline: task grant, policy, argument constraints, rate limit,
  human gate. First failing check decides; every decision is audited.
- Task-scoped, expiring HMAC grants with per-grant and per-task revocation.
- Declarative YAML policy with full-match regex, allow-lists, numeric bounds, length
  caps, required and unknown-argument rules, and per-tool rate limits.
- Human approvals bound to the exact call fingerprint: single use, expiring, and never
  approvable by the requesting agent.
- Session taint tracking: egress tools need approval after untrusted content is read.
- HMAC-chained audit log with `aggw verify-audit`.
- HTTP API (FastAPI) with separate agent and operator credentials, request IDs and
  Prometheus metrics.
- MCP stdio proxy that filters `tools/list` and enforces every `tools/call`.
- Agent loop with pluggable model providers (OpenAI-compatible, Azure OpenAI, scripted
  mock) and tool schemas generated from policy.
- Attack-scenario evaluation (`aggw eval`): 23 attacks across injection, excessive
  agency, argument abuse, approval abuse, credential abuse, resource abuse and audit
  integrity, plus benign scenarios that guard against false positives. Runs in CI.
- Structured JSON decision logs and optional OpenTelemetry spans.
- Offline demo, Docker image, docker compose, CI on Python 3.11 to 3.13, CodeQL,
  dependency audit and Dependabot.

[0.1.0]: https://github.com/darshansatpathy/agent-guardrails-gateway/releases/tag/v0.1.0
