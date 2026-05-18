#!/bin/bash
# Stage pre-built linux/musl binaries into the docker build
# context, then build the image. Run from repo root:
#   bash sec/docker/build.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
TARGET=target/x86_64-unknown-linux-musl/release

cross build -p drift -p drift-mosh -p attack-relay -p http-probe \
  -p mesh-listener -p mesh-sender \
  --release --target x86_64-unknown-linux-musl

cp "$TARGET/drift"             sec/docker/
cp "$TARGET/drift-mosh-server" sec/docker/
cp "$TARGET/drift-mosh-client" sec/docker/
cp "$TARGET/attack-relay"      sec/docker/
cp "$TARGET/http-probe"        sec/docker/
cp "$TARGET/mesh-listener"     sec/docker/
cp "$TARGET/mesh-sender"       sec/docker/

docker build --platform linux/amd64 -t drift-sec:latest sec/docker
rm sec/docker/{drift,drift-mosh-server,drift-mosh-client,attack-relay,http-probe,mesh-listener,mesh-sender}
echo "image: drift-sec:latest"
