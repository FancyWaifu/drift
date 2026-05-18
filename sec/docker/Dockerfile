# Minimal runtime image for the security testbed. Bundles
# pre-built drift, drift-mosh-server, drift-mosh-client, and
# attack-relay binaries. Cross-build them first from the host
# (see sec/docker/build.sh).
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tcpdump \
        iproute2 \
        iputils-ping \
        netcat-openbsd \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY drift                /usr/local/bin/
COPY drift-mosh-server    /usr/local/bin/
COPY drift-mosh-client    /usr/local/bin/
COPY attack-relay         /usr/local/bin/
RUN chmod +x /usr/local/bin/*

WORKDIR /work
