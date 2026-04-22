# Multi-stage build: compile the drift-bench binary in a
# full Rust toolchain image, then copy just the binary into a
# minimal runtime for benchmarking.
#
# The build stage pulls the *entire* workspace because
# drift-bench depends on the drift crate via a path dep; no
# prebuilt binaries on crates.io. Expect the first build to
# take a few minutes — subsequent runs are cached by Docker's
# layer system.

FROM rust:1-slim-bookworm AS builder
WORKDIR /usr/src/drift

# System deps for boringtun + quinn + rustls-ring.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the workspace. .dockerignore should exclude target/ so
# we don't upload gigabytes of host artifacts.
COPY . .

# Build just the bench binary in release mode.
RUN cargo build --release -p drift-bench --bin drift-bench

# ─────────────────────────────────────────────────────────────
# Runtime stage: minimal image with the binary + the tools
# needed to shape the network (netem via iproute2).

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/drift/target/release/drift-bench /usr/local/bin/drift-bench

# Default entrypoint; docker-compose overrides via `command`
# to pass the right --protocol / --mode / --workload.
ENTRYPOINT ["/usr/local/bin/drift-bench"]
