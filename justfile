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

# Build the server binary and the Docker image.
release: build-server docker-build

# Build the server Docker image.
docker-build:
    docker build -t {{image}} .

# Run the server container in the foreground with ephemeral tmpfs storage (data lost on exit).
docker-run: docker-build
    @[ -n "${OPAQ_MASTER_KEY:-}" ] || { echo "OPAQ_MASTER_KEY must be set in your shell" >&2; exit 1; }
    docker run --rm --init --name {{container}} -p {{host_port}}:6727 --tmpfs /data:size=256m,uid=1500,gid=1500,mode=0700 -e OPAQ_MASTER_KEY {{image}}; rc=$?; case $rc in 130|143) echo "opaq-server stopped (signal)" >&2; exit 0;; *) exit $rc;; esac

# Deploy the server container locally in the background with persistent Docker volume storage.
docker-deploy: docker-build
    @[ -n "${OPAQ_MASTER_KEY:-}" ] || { echo "OPAQ_MASTER_KEY must be set in your shell" >&2; exit 1; }
    docker rm -f {{container}} >/dev/null 2>&1 || true
    docker run -d --init --name {{container}} -p {{host_port}}:6727 -v {{volume}}:/data -e OPAQ_MASTER_KEY {{image}}

# Rebuild and redeploy the local server container.
docker-restart: docker-stop docker-deploy

# Stop and remove the local server container if it exists.
docker-stop:
    docker rm -f {{container}} >/dev/null 2>&1 || true

# Follow local server container logs.
docker-logs:
    docker logs -f {{container}}
