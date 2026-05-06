# drift-vpn build + runtime in one image.
#
# Builder: rust:1-slim-bookworm. Compiles only the `drift-vpn`
# bin (not the whole workspace) to keep build time down.
#
# Runtime: debian:bookworm-slim + iproute2 (for ip / ping
# debugging) + the drift-vpn binary. /dev/net/tun is mounted
# at container start; the bin manipulates it.

FROM rust:1-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/drift
COPY . .

RUN cargo build --release -p drift-vpn --bin drift-vpn


FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates iproute2 iputils-ping iputils-tracepath iperf3 iptables ethtool \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/drift/target/release/drift-vpn /usr/local/bin/drift-vpn

ENTRYPOINT ["/usr/local/bin/drift-vpn"]
