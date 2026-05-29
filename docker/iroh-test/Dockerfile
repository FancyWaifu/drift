# Drop in the pre-built musl drift-bench binary (compiled on
# the host via `cross build -p drift-bench --target x86_64-
# unknown-linux-musl --release`). Static musl linkage means no
# runtime deps beyond what's needed for the shell wrapper.

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash python3 procps \
 && rm -rf /var/lib/apt/lists/*

# Build context is the docker/iroh-test/ dir; binary staged
# there by the build script via `cp ../../target/x86_64-
# unknown-linux-musl/release/drift-bench ./drift-bench`.
COPY drift-bench /usr/local/bin/drift-bench
RUN chmod +x /usr/local/bin/drift-bench

ENTRYPOINT ["/bin/bash"]
