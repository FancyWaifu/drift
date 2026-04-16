# Multi-stage build: compile DRIFT in release mode, then ship a slim
# runtime image with the Linux networking tools we need for test
# orchestration (tc netem, iptables, iproute2, tcpdump).

FROM rust:1-slim-bookworm AS builder
WORKDIR /build
# Copy just the manifests first so dependency builds are cached.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/lib.rs && \
    cargo build --release 2>/dev/null || true
# Now copy the real sources and build.
COPY src ./src
COPY examples ./examples
COPY benches ./benches
COPY tests ./tests
RUN cargo build --release --examples

FROM debian:bookworm-slim AS runtime
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 \
        iptables \
        tcpdump \
        iputils-ping \
        netcat-openbsd \
        procps \
        ca-certificates \
        curl \
        redis-tools \
        openssh-client \
        openssh-server \
        sshpass && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/examples/drift-send  /usr/local/bin/
COPY --from=builder /build/target/release/examples/drift-recv  /usr/local/bin/
COPY --from=builder /build/target/release/examples/drift-mesh  /usr/local/bin/
COPY --from=builder /build/target/release/examples/drift-relay /usr/local/bin/
COPY --from=builder /build/target/release/examples/big-send     /usr/local/bin/
COPY --from=builder /build/target/release/examples/scale-client /usr/local/bin/
COPY --from=builder /build/target/release/examples/scale-server /usr/local/bin/
COPY --from=builder /build/target/release/examples/drift-ring       /usr/local/bin/
COPY --from=builder /build/target/release/examples/drift-dir-server /usr/local/bin/
COPY --from=builder /build/target/release/examples/drift-dir-client /usr/local/bin/
COPY --from=builder /build/target/release/examples/drift-peer       /usr/local/bin/
COPY --from=builder /build/target/release/examples/drift-tun        /usr/local/bin/
COPY --from=builder /build/target/release/examples/lossy-proxy      /usr/local/bin/
COPY --from=builder /build/target/release/examples/resumption-server /usr/local/bin/
COPY --from=builder /build/target/release/examples/resumption-client /usr/local/bin/
COPY --from=builder /build/target/release/examples/drift-reconnect-node /usr/local/bin/
COPY --from=builder /build/target/release/examples/drift-mesh-node-v2  /usr/local/bin/
COPY --from=builder /build/target/release/examples/drift-churn-node    /usr/local/bin/

WORKDIR /work
ENV RUST_LOG=drift=info
CMD ["drift-recv"]
