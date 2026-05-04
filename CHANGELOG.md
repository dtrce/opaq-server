# Changelog

All notable changes to opaq-server are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-04

Initial public release.

### Added
- HTTP server on port 6727 (Salvo + Tokio).
- SQLite storage (bundled, single-file `/data/opaq.db`).
- AES-256-GCM encryption at rest for secret values; master key derived from `OPAQ_MASTER_KEY` passphrase via Argon2id.
- API key authentication with HMAC-SHA256 hashed keys (peppered).
- Global role model: `reader`, `writer`, `admin`.
- Auto-creation of root admin on first start; key printed once to stdout.
- Hierarchical secret paths with strict 3- or 4-segment validation (`/workspace/project/key` and `/workspace/project/env/key`).
- Project-scoped vs env-scoped reads with env-wins merge semantics.
- Secret commands: `put`, `get`, `delete`, `list` (project + env variants).
- Principal commands: `upsert`, `list`, `revoke`, `rotate`, `me`.
- Per-principal TTL with expiry enforced at auth time.
- Refusal to revoke or demote the last active admin.
- `/healthz` liveness endpoint.
- Structured JSON error responses (`force_json_error` middleware).
- Dockerfile (debian:bookworm-slim runtime) with non-root `opaq` user and `gosu` entrypoint that chowns `/data` on start.
- `justfile` recipes for build, image build, foreground run (tmpfs), background deploy (volume), logs, and stop.

### Security
- Master key never persisted; required via env on every start.
- API keys hashed with HMAC-SHA256 using a server pepper; raw keys returned only at creation/rotation.
- Constant-time key comparison via `subtle`.
- Sensitive material wrapped in `Zeroizing` to clear memory on drop.

[Unreleased]: https://github.com/dtrce/opaq-server/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dtrce/opaq-server/releases/tag/v0.1.0
