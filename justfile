set shell := ["bash", "-uc"]

image := env_var_or_default("IMAGE", "opaq-server")
container := env_var_or_default("CONTAINER", "opaq-server")
host_port := env_var_or_default("PORT", "6727")
volume := env_var_or_default("VOLUME", "opaq-data")

alias build := build-server
alias deploy := docker-deploy
alias run := docker-run
alias stop := docker-stop
alias logs := docker-logs

# Show available recipes.
default:
    @just --list

# Build the server release binary at target/release/opaq-server.
build-server:
    cargo build --release --bin opaq-server

# Run release pre-flight checks (fmt, clippy, tests, release build).
release-check:
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    cargo test
    cargo build --release --bin opaq-server

# Verify, tag v$VERSION locally, and push to trigger release workflow. Bump Cargo.toml version manually first.
release VERSION:
    @set -e; \
    if ! git diff --quiet || ! git diff --cached --quiet; then echo "error: working tree not clean" >&2; exit 1; fi; \
    if [ "$(git rev-parse --abbrev-ref HEAD)" != "main" ]; then echo "error: must be on main branch" >&2; exit 1; fi; \
    cargo_ver=$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml); \
    if [ "$cargo_ver" != "{{VERSION}}" ]; then echo "error: Cargo.toml version ($cargo_ver) != {{VERSION}} — bump it first" >&2; exit 1; fi; \
    if git rev-parse "v{{VERSION}}" >/dev/null 2>&1; then echo "error: tag v{{VERSION}} already exists" >&2; exit 1; fi; \
    git fetch origin --tags; \
    if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then echo "error: local main not in sync with origin/main" >&2; exit 1; fi
    just release-check
    git tag -a "v{{VERSION}}" -m "opaq-server v{{VERSION}}"
    @echo ""
    @echo "tagged v{{VERSION}} locally. push to trigger release workflow:"
    @echo "  git push origin v{{VERSION}}"

# Build the server Docker image.
docker-build:
    docker build -t {{image}} .

# Run the server container in the foreground with ephemeral tmpfs storage (data lost on exit).
docker-run: docker-build
    @[ -n "${OPAQ_MASTER_KEY:-}" ] || { echo "OPAQ_MASTER_KEY must be set in your shell" >&2; exit 1; }
    docker run --rm --init --name {{container}} -p 127.0.0.1:{{host_port}}:6727 --tmpfs /data:size=256m,uid=1500,gid=1500,mode=0700 -e OPAQ_MASTER_KEY -e OPAQ_HOST=0.0.0.0 {{image}}; rc=$?; case $rc in 130|143) echo "opaq-server stopped (signal)" >&2; exit 0;; *) exit $rc;; esac

# Deploy the server container locally in the background with persistent Docker volume storage.
docker-deploy: docker-build
    @[ -n "${OPAQ_MASTER_KEY:-}" ] || { echo "OPAQ_MASTER_KEY must be set in your shell" >&2; exit 1; }
    docker rm -f {{container}} >/dev/null 2>&1 || true
    docker run -d --init --name {{container}} -p 127.0.0.1:{{host_port}}:6727 -v {{volume}}:/data -e OPAQ_MASTER_KEY -e OPAQ_HOST=0.0.0.0 {{image}}

# Rebuild and redeploy the local server container.
docker-restart: docker-stop docker-deploy

# Stop and remove the local server container if it exists.
docker-stop:
    docker rm -f {{container}} >/dev/null 2>&1 || true

# Follow local server container logs.
docker-logs:
    docker logs -f {{container}}
