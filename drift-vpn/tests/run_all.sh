#!/usr/bin/env bash
# Run every drift-vpn integration test in sequence.
# Reports per-test pass/fail and exits nonzero if any failed.
#
# Wall time: ~5–7 min depending on the bench machine.
# Networking is reset between tests (each uses its own
# bridge / subnet) so they don't interfere.

set -o pipefail
# Deliberately not `-u`. With empty arrays (e.g. all tests
# pass, FAIL=()), `set -u` errors on `"${FAIL[@]}"` because
# bash treats unset and empty arrays the same under that
# flag. The risk of a typo'd variable name is small in this
# short script.
TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
DRIFT_VPN_DIR="$(dirname "$TESTS_DIR")"
cd "$DRIFT_VPN_DIR/.."  # workspace root

TESTS=(
    "two_node.sh"
    "two_node_fallback.sh"
    "fallback_stress.sh"
    "three_node_mesh.sh"
    "throughput.sh"
    "restart.sh"
    "spoof.sh"
    "lossy.sh"
    "stability.sh"
    "failover_basic.sh"
    "failover_flap.sh"
)

# Force a single image build at the start so the per-test
# build is a no-op cache hit.
echo "==> One-time image build"
if ! docker build -f drift-vpn/Dockerfile -t drift-vpn:test . >/dev/null 2> /tmp/drift-vpn-build.err; then
    echo "FAIL: docker build"
    tail -20 /tmp/drift-vpn-build.err
    exit 1
fi

# Cleanup any stragglers from previous runs.
docker ps -a --format '{{.Names}}' | grep -E '^drift-vpn-' \
    | xargs -r docker rm -f >/dev/null 2>&1 || true

PASS=()
FAIL=()
for t in "${TESTS[@]}"; do
    echo
    echo "================================================================"
    echo "==  $t"
    echo "================================================================"
    # Pre-test settle: Docker's rm is asynchronous, so a
    # leftover network from the previous test can briefly
    # block the next test's `network create`. A short sleep +
    # explicit sweep gives Docker time to finish cleaning up.
    docker ps -a --format '{{.Names}}' | grep -E '^drift-vpn-' \
        | xargs -r docker rm -f >/dev/null 2>&1 || true
    docker network ls --format '{{.Name}}' | grep -E '^drift-vpn-' \
        | xargs -r docker network rm >/dev/null 2>&1 || true
    sleep 1
    # Capture full output. Pass = the test exited 0 AND emitted
    # a `^RESULT:` line anywhere. Fail otherwise. Some tests
    # have multi-line RESULT blocks, so don't restrict to tail.
    out=$(bash "$TESTS_DIR/$t" 2>&1)
    rc=$?
    if [ $rc -eq 0 ] && echo "$out" | grep -qE "^RESULT:"; then
        PASS+=("$t")
    else
        FAIL+=("$t")
        echo "$out" | tail -10 | sed 's/^/    /'
    fi
done

echo
echo "================================================================"
echo "Summary"
echo "================================================================"
for t in "${PASS[@]}"; do
    echo "  PASS  $t"
done
for t in "${FAIL[@]}"; do
    echo "  FAIL  $t"
done

echo
echo "${#PASS[@]} pass / ${#FAIL[@]} fail (of ${#TESTS[@]} tests)"
[ "${#FAIL[@]}" -eq 0 ]
