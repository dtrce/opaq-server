FROM rust:1-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --bin opaq-server

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*

ENV OPAQ_HOST=0.0.0.0
ENV OPAQ_PORT=6727
ENV OPAQ_DB=/data/opaq.db

RUN mkdir -p /data && groupadd -r -g 1500 opaq && useradd -r -u 1500 -g opaq opaq

COPY --from=builder /app/target/release/opaq-server /usr/local/bin/opaq-server

RUN chown -R opaq:opaq /data
USER opaq

EXPOSE 6727
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/bin/sh", "-c", "wget -qO- http://localhost:6727/healthz || exit 1"]

CMD ["/usr/local/bin/opaq-server"]
