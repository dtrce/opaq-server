# opaq

A small self-hosted config & secret store. One Rust server, one CLI, SQLite for storage, AES-256-GCM at rest. A stolen database is useless without the master key.

> ⚠️ **Not for production.** Hobby project. Not audited or hardened. Use for learning or hobby setups — don't put real production secrets in it.
>
> 🪟 **Not tested on Windows.** Developed on macOS and Linux. The CLI path resolution, `justfile`, and Docker workflow assume a POSIX shell. **Looking for Windows testers** — open an issue with what worked, what didn't, and your platform (PowerShell / WSL / Git Bash, Windows version). PRs welcome.

## What it does

- Store strings or JSON blobs at hierarchical paths.
- Hand out API keys with global roles: `reader`, `writer`, or `admin`.
- Pull secrets back as JSON, raw values, or `KEY=VAL` lines for `--env-file` / `eval`.

## Quick start

```bash
# 1. Generate a master-key passphrase (≥32 ASCII alphanumeric chars).
export OPAQ_MASTER_KEY=$(opaq genkey)            # 64 random alphanumeric chars

# 2. Run the server (Docker)
just deploy                # builds image + starts container on :6727
# or natively:
cargo run --release --bin opaq-server
# On first start with an empty DB, the root admin API key is printed once.

# 3. Configure CLI
opaq login --server http://127.0.0.1:6727 --key opaq_...

# 4. Use it
opaq set /acme/api/prod/STRIPE_KEY --string sk_live_xxx
opaq get /acme/api/prod/STRIPE_KEY --raw
opaq env /acme/api/prod                  # KEY=VAL lines
eval "$(opaq env /acme/api/prod --shell)"
```

`opaq help` prints a cheatsheet. `opaq <command> --help` gives details for a specific command.

## Path model

opaq is deliberately rigid about paths. This is a feature, not a TODO:

- **Exactly 3 or 4 segments.** No deeper nesting, no flat keys, no free-form namespaces.
  - 3 segments → `/workspace/project/key` — **project-scoped** (shared across every env in the project)
  - 4 segments → `/workspace/project/env/key` — **env-scoped** (visible only inside that env)
- **Scope paths drop the trailing key.** `list` and `env` operate on `/workspace/project` or `/workspace/project/env`.
- **Each segment** must match `[a-zA-Z0-9_-]{1,64}` — case-sensitive, no slashes, no Unicode, no spaces. `Workspace` ≠ `workspace`.
- **No path inheritance at `get`.** Lookups are exact; there is no fallback to a project-scoped key of the same name.
- **`opaq list /ws/proj/env` merges by default.** Env-scoped listings include the project-scoped (3-segment) rows alongside the matching env-scoped (4-segment) rows, so you see the full effective scope. Pass `--no-merge` to restrict the listing to env-scoped rows only.
- **`opaq env` merges with env-wins semantics.** Returns project-scoped (3-segment) + matching env-scoped (4-segment) entries as one `KEY=VAL` stream. When the same key exists at both scopes, the env-scoped value wins silently. Stdout is pipe-clean — safe to redirect into `.env` or pass to `eval`.

Path structure is organization, not an access boundary. Roles are global for v1.

## Role model

Each principal has one global role plus an optional expiry.

- **reader** — list/export/get all secrets.
- **writer** — reader + set and delete secrets.
- **admin** — writer + create/list/revoke principals.

The first admin is auto-created on first server start and printed once as `Root admin API key: opaq_...`.

### TTL

Pass `--ttl <duration>` on `opaq principal set` to time-box a key. Format: `30d`, `12h`, `60m`, `3600s`, or a bare integer (seconds). Omitted = no expiry. Expired keys fail authentication; the row stays in the DB for audit.

```bash
opaq principal set temp-deploy --role writer --ttl 24h
```

**Other guarantees:**
- Revoking the last admin key is refused (`cannot revoke the last admin key`).
- Key revocation sets `revoked_at`; subsequent auth attempts fail immediately.
- No workspace/project/env permissions in v1. Path structure is not an access boundary.

## Security

Read this before deploying anywhere — even on a hobby box.

> 🛡️ **A stolen DB alone is safe.** `opaq.db` cannot be decrypted without `OPAQ_MASTER_KEY`.
>
> 🔐 **Lose an API key, lose that principal's access.** API keys are stored only as one-way fingerprints; the plaintext key is shown exactly once at creation. An admin can mint a fresh key for the same principal with `opaq principal rotate <NAME>`, or create a new principal with `opaq principal set <NAME> --role ...`. Existing secrets are untouched.

### How encryption works (plain)

Think of opaq as one locked box plus a guest list.

- **Big box** = your secrets. Locked with a **master key**.
- **Master key** comes from `OPAQ_MASTER_KEY` (operator-supplied; required on every start).
- **API keys** identify principals. The principal's role decides whether the server may read, write, or manage keys.

```
  OPAQ_MASTER_KEY  +  Authorization: Bearer opaq_...
         |                         |
         v                         v
  unlock / lock secrets      find principal + role
```

What's in the DB if someone steals it:

- a public pepper/salt (useless alone)
- fingerprints of API keys (one-way; cannot reverse to API key)
- locked secrets (need `OPAQ_MASTER_KEY` to open)

Without `OPAQ_MASTER_KEY`, nothing opens. API keys are 256 bits of entropy — guessing is infeasible.

### Crypto details

- **Master key:** `OPAQ_MASTER_KEY` is a passphrase of **≥32 ASCII alphanumeric characters** (`[a-zA-Z0-9]`). The server derives the AES-256 value-encryption key with **Argon2id** (m=64 MiB, t=3, p=1) using a per-instance random 32-byte `kdf_salt` stored in `instance_meta`. Memory-hardness defeats GPU/ASIC brute-force even when the passphrase has lower entropy than ideal.
- **API key format:** `opaq_<64 hex chars>` — 32 random bytes, ~256 bits of entropy. Authenticates principals; does not encrypt data.
- **Fingerprint:** `key_hash = HMAC-SHA256(api_key, key_pepper)`. `key_pepper` is a per-instance public salt in `instance_meta`. Used for `O(1)` lookup; HMAC's one-way property protects API keys against reversal from a DB dump. Acceptable as single-iteration HMAC because the key itself is high-entropy — never reuse this scheme for human passwords.
- **Value seal:** AES-256-GCM with a fresh random 12-byte nonce per write. Stored as `secrets.encrypted_val` + `secrets.nonce`. No per-secret DEK envelope; values are sealed directly under the derived master key.
- **Post-quantum:** AES-256-GCM gives 128-bit security under Grover. HMAC-SHA256 and Argon2id likewise. No asymmetric primitives — Shor does not apply.
- **Master-key rotation:** not implemented. Would require re-encrypting every secret value.
- **Plaintext API key** is shown exactly once (on `principal set` (when creating), `principal rotate`, or first-server-start root bootstrap). Capture it then.

### Transport

The server speaks plain HTTP. **There is no built-in TLS.** Run it behind a reverse proxy (Caddy, nginx, Traefik), or restrict it to localhost / a private network. Default bind is `127.0.0.1:6727`, including the Docker image. The local `just docker-run` / `just docker-deploy` recipes publish the container on host loopback only. Override with `OPAQ_HOST=0.0.0.0` only after you've put TLS in front. Auth is `Authorization: Bearer opaq_...` on every request.

### Threat model

opaq protects (a) secret values against anyone with read-only DB access but no `OPAQ_MASTER_KEY`, and (b) API access by anyone without a valid key. It does **not** protect against host compromise, network sniffing without TLS, a leaked `OPAQ_MASTER_KEY`, a malicious admin, or a valid reader key reading all secrets.

Not implemented: rate limiting, brute-force lockout, secret rotation / versioning / history (`set` overwrites in place), scoped read/write isolation, HA / replication / online backup, CSRF / origin checks. Treat opaq as an early-stage tool for personal use, internal experimentation, and learning — not a vault.

## Configuration

**Server** (environment variables, all optional unless marked):

| Var | Default | Purpose |
|-----|---------|---------|
| `OPAQ_HOST` | `127.0.0.1` | Bind address |
| `OPAQ_PORT` | `6727` | Bind port |
| `OPAQ_DB` | `opaq.db` | SQLite file path |
| `OPAQ_MASTER_KEY` | **required** | Passphrase, ≥32 ASCII alphanumeric chars; passed through Argon2id (per-instance salt) into the AES-256 value-encryption key |

**CLI:** config stored at `~/.config/opaq/config.json` (Linux + macOS). Created by `opaq login`.

## REST API

opaq is a plain JSON HTTP API. The CLI is a thin wrapper over it. See **[`docs/API.md`](docs/API.md)** for the full reference: endpoints, request/response shapes, auth, and curl examples.

Quick taste:

```bash
curl -fsSL https://opaq.example.com/api/v1/me \
  -H "Authorization: Bearer $OPAQ_KEY"
```

## Building from source

```bash
cargo build --release            # both binaries
just build                       # same, via justfile
```

Binaries land at `target/release/opaq` (CLI) and `target/release/opaq-server`.

## Sample use cases

### 1. Replace ad-hoc `.env` files in personal dev

```bash
opaq set /me/myapp/dev/DATABASE_URL --string postgres://localhost/myapp
opaq set /me/myapp/dev/STRIPE_KEY   --string sk_test_xxx
cargo run --env-file <(opaq env /me/myapp/dev)
```

No plaintext file lands on disk; the FIFO closes after `cargo` exits.

### 2. Read-only CI bot

```bash
# one-time, as admin
opaq principal set github-ci --role reader   # save the printed key into GH secrets
# or time-boxed: opaq principal set github-ci --role reader --ttl 30d

# in CI, with $OPAQ_KEY set from a GH secret
opaq login --server $OPAQ_URL --key $OPAQ_KEY
eval "$(opaq env /acme/api/prod --shell)"
./run-deploy.sh
```

### 3. Homelab / shared services

One opaq server behind your reverse proxy, many small services pulling secrets:

```bash
opaq principal set grafana --role reader
opaq principal set jellyfin --role reader
# v1 roles are global: reader keys can read every secret.
```

### 4. Host opaq on Fly.io / Railway

Single Rust binary in a small Docker image. Persist the DB, set `OPAQ_MASTER_KEY` in the platform's secret manager, and capture the root admin API key from server logs on first start.

```bash
# Fly: persistent volume for the SQLite DB
fly launch --image opaq-server --no-deploy
fly volumes create opaq_data --size 1
fly deploy

# Railway: attach a volume mounted at /data, expose port 6727,
# set OPAQ_DB=/data/opaq.db.
```

In every other Fly/Railway app, set a single `OPAQ_KEY` secret and have the app pull its real config at boot. Rotating an API key is one command.

### 5. Pull secrets at container start

Bake `opaq` into your app image and have it fetch secrets just before `exec`'ing the real process. The app itself never sees the API key — only the resolved env vars.

```dockerfile
# Dockerfile (your app's image)
FROM debian:bookworm-slim
COPY --from=ghcr.io/yourorg/opaq:latest /usr/local/bin/opaq /usr/local/bin/opaq
COPY docker-entrypoint.sh /usr/local/bin/
COPY ./your-app /usr/local/bin/your-app
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["your-app"]
```

```sh
#!/usr/bin/env sh
# docker-entrypoint.sh
set -eu

: "${OPAQ_URL:?OPAQ_URL not set}"
: "${OPAQ_KEY:?OPAQ_KEY not set}"
: "${OPAQ_PATH:?OPAQ_PATH not set (e.g. /acme/api/prod)}"

opaq login --server "$OPAQ_URL" --key "$OPAQ_KEY" >/dev/null

# Export the project+env into this process's env, then drop the API key
# so the child process never sees it.
eval "$(opaq env "$OPAQ_PATH" --shell)"
unset OPAQ_KEY

exec "$@"
```

Ship `OPAQ_URL`, `OPAQ_KEY`, and `OPAQ_PATH` via the platform's secret/env mechanism. Everything else (DB URL, Stripe key, …) lives in opaq and shows up as plain env vars to your app.

## License

MIT — see [LICENSE](LICENSE).
