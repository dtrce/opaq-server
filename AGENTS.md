# AGENTS.md — opaq-server

Guidance for AI coding agents working in this repo.

## Purpose

Self-hosted config/secret store. Single Rust binary, SQLite storage, AES-256-GCM at rest. REST API consumed by the [opaq CLI](https://github.com/dtrce/opaq-cli) and direct HTTP clients.

Hobby project — **not production-hardened**. Not audited.

## Layout

```
src/main.rs            # salvo router wiring, app bootstrap, master-key load
src/auth.rs            # bearer-token middleware, role checks
src/config.rs          # env-var config (PORT, OPAQ_MASTER_KEY, DB path)
src/db.rs              # rusqlite connection pool, schema migrations
src/crypto.rs          # argon2 KDF, AES-256-GCM seal/open
src/secrets.rs         # secret CRUD + listing + project/env merge logic
src/error.rs           # `OpaqError` + JSON error response writer
src/commands/          # one file per HTTP handler (get_secret, list_secrets, ...)
src/commands/shared.rs # request helpers, path validation
docs/API.md            # REST endpoint reference (source of truth for CLI)
tests/integration.rs   # placeholder smoke test
Dockerfile             # multi-stage build
justfile               # build / docker recipes
```

Single `[[bin]]` named `opaq-server`. `publish = false` — never goes to crates.io.

## Common commands

```sh
cargo build --release --bin opaq-server   # → target/release/opaq-server
cargo test
cargo clippy --all-targets
cargo fmt

just build-server          # alias for cargo build --release
just docker-build          # builds Docker image
just docker-run            # foreground container, requires OPAQ_MASTER_KEY
just docker-deploy         # detached container
just docker-logs           # follow container logs
```

## Runtime requirements

- `OPAQ_MASTER_KEY` env var: ≥32 ASCII alphanumeric chars. Required at startup. Used to derive the per-DB encryption key via Argon2id. Server panics if absent.
- SQLite DB: defaults to `./opaq.db`. Container mounts `/data`.
- First boot with an empty DB prints the root admin API key once to stdout — capture it.

## Conventions

- **No `unwrap()` or `unsafe` outside tests.** Use `?`, `ok_or`, `map_err`, or pattern-match. The crypto and DB layers especially must propagate errors — a panic on a malformed value would crash the server for all clients.
- All HTTP handlers return `Result<T, OpaqError>`. `OpaqError` serializes to `{"error": "msg"}` with the right HTTP status.
- API keys are stored as HMAC-SHA256 digests, never plaintext. Plaintext shown once at create/rotate.
- Secrets at rest: AES-256-GCM, random 12-byte nonce, key derived per-DB via Argon2id from `OPAQ_MASTER_KEY` + a salt stored in the DB.
- Constant-time comparison for secret material (`subtle::ConstantTimeEq`).
- `zeroize` sensitive byte buffers — see `Zeroizing<Vec<u8>>` usage.
- New routes: add a handler in `src/commands/`, wire in `main.rs` router, document in `docs/API.md`.

## API contract

Base path `/api/v1`. Auth via `Authorization: Bearer <key>`. Roles: `reader` < `writer` < `admin`.

Path model:
- 3 segments: `/{ws}/{proj}/{key}` — project-scoped secret (default across envs)
- 4 segments: `/{ws}/{proj}/{env}/{key}` — env-scoped (overrides project default)

When changing endpoints, update `docs/API.md` AND notify the CLI repo — they're versioned independently.

## What not to do

- Don't drop `publish = false`. This crate is server-only and includes deployment files; it must not land on crates.io.
- Don't merge CLI code (`clap`, `comfy-table`, `dirs`, `reqwest`) back into this repo — that split was deliberate.
- Don't change the master-key derivation parameters (Argon2 cost, salt format) without a migration path. Existing DBs become unreadable.
- Don't log secret values. `tracing` is enabled — be careful what gets formatted into spans/events.
- Don't commit `opaq.db*`, `*.db.key`, or `fly.toml` (already in `.gitignore`).
