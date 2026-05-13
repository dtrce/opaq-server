# Changelog

All notable changes to opaq-server are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-05-13

### Security
- Bind AES-256-GCM ciphertexts to per-secret associated data (`opaq-secret-v1\0{path}\0{type}`). Prevents ciphertext swap/move attacks across rows even with DB write access.
- Boot-time migration re-wraps legacy ciphertexts in place; reads transparently use the new AAD. Old ciphertexts no longer decrypt after migration.
- Last-admin protection now ignores expired admins. Expired admin rows no longer satisfy the "at least one admin remaining" gate during revoke/demote.
- JSON body size limit enforced by the parser (`parse_json_with_max_size`, 1 MiB) instead of trusting the `Content-Length` header. Closes the bypass where a small `Content-Length` was paired with a larger streamed body.
- Docker image defaults `OPAQ_HOST=127.0.0.1`. `just docker-run` / `just docker-deploy` publish the container on host loopback (`127.0.0.1:{port}:6727`) and set `OPAQ_HOST=0.0.0.0` only inside the container namespace.
- `SecretData.value` wrapped in `Zeroizing<String>` so plaintext clears on drop in the get/list paths.

### Changed
- Removed `.unwrap()` from production code paths (`src/main.rs` security-headers middleware now uses `HeaderValue::from_static`). No `unsafe` anywhere in `src/`.

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

[Unreleased]: https://github.com/dtrce/opaq-server/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/dtrce/opaq-server/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dtrce/opaq-server/releases/tag/v0.1.0
