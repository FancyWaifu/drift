# Federation-discovery test rig.
#
# Builds the four binaries we exercise in the test:
#   * drift                — bridge runner (`drift bridge --listen … --federate …`)
#   * drift-mosh-server    — service speaking through a bridge
#   * drift-mosh-client    — dials by pubkey, resolves route via drift.toml
#   * drift-config         — keygen + drift.toml writer
#
# Single image, role chosen by container CMD in docker-compose.yml.

FROM rust:1-slim-bookworm AS builder
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cargo build --release \
    -p drift --bin drift \
    -p drift-mosh --bin drift-mosh-server --bin drift-mosh-client \
    -p drift-config --bin drift-config

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates iproute2 iputils-ping netcat-openbsd procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/drift              /usr/local/bin/
COPY --from=builder /build/target/release/drift-mosh-server  /usr/local/bin/
COPY --from=builder /build/target/release/drift-mosh-client  /usr/local/bin/
COPY --from=builder /build/target/release/drift-config       /usr/local/bin/

WORKDIR /work
ENV RUST_LOG=info,drift_mosh_server=info
