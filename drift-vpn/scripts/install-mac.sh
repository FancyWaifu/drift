#!/bin/bash
# install-mac.sh — local-dev build + install for drift-vpn on macOS.
#
# What this fixes: cargo-built binaries on Apple Silicon have only
# ad-hoc codesign by default, AND a plain `cp` of the binary
# clobbers the signature's extended attributes. Result: `sudo
# drift-vpn up` silently dies with `zsh: killed` (the kernel
# rejects the binary's exec). This script:
#   1. Builds drift-vpn natively in release mode.
#   2. Ad-hoc re-signs the output binary (`codesign -s -`).
#   3. Installs it to /usr/local/bin/drift-vpn with sudo.
#   4. Re-signs the installed copy (cp/install strip xattrs).
#   5. Verifies the installed binary's signature.
#
# Use this once after `git clone` and after every change to drift
# or drift-vpn source. CI / pre-built release tarballs get a real
# Developer ID + notarization; this is dev-experience only.

set -euo pipefail

# Move to repo root (this script lives at drift-vpn/scripts/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/../.."

echo "=== building drift-vpn (release) ==="
cargo build --release -p drift-vpn

BUILT="target/release/drift-vpn"
INSTALLED="/usr/local/bin/drift-vpn"

echo ""
echo "=== ad-hoc signing the built binary ==="
codesign --force --deep -s - "${BUILT}"

echo ""
echo "=== installing to ${INSTALLED} (requires sudo) ==="
sudo install -m 755 "${BUILT}" "${INSTALLED}"

echo ""
echo "=== re-signing the installed copy ==="
# `install` and `cp` both clobber the codesign extended attribute
# on macOS, so the signature embedded in the build output gets
# stripped during the copy. Re-signing the installed file is
# what makes `sudo drift-vpn up` work — without this, the kernel
# kills the binary on exec.
sudo codesign --force --deep -s - "${INSTALLED}"

echo ""
echo "=== verifying ==="
codesign --verify --verbose "${INSTALLED}"
"${INSTALLED}" --help | head -1

echo ""
echo "Done. Try: sudo drift-vpn up"
