# Two-bridge mesh demo. Single binary that runs as either a
# bridge or a client based on $NODE_ROLE; identities are
# deterministic from $NODE_INDEX so 12 containers can come up
# in any order and still find each other.

FROM rust:1-slim-bookworm AS builder
WORKDIR /usr/src/drift

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cargo build --release -p drift --example two-bridge-demo

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates iproute2 iputils-ping netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/drift/target/release/examples/two-bridge-demo \
    /usr/local/bin/two-bridge-demo

ENV RUST_LOG=drift=warn,two_bridge_demo=info

CMD ["two-bridge-demo"]
