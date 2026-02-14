#!/bin/bash
# CI smoke test for the API Boundary Node recovery container.
# Builds the image, starts it, waits for readiness, and verifies
# that a canister query through it succeeds.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTAINER_NAME="api-bn-test-$$"
IMAGE_NAME="api-boundary-node"
IMAGE_TAG="test"
MAX_WAIT=300 # 5 minutes for registry sync + replica discovery

cleanup() {
    echo "Cleaning up..."
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
}
trap cleanup EXIT

# ─── Pre-check: stop anything already on port 8080 ───
if curl -sf http://localhost:8080/api/v2/status -o /dev/null 2>/dev/null; then
    echo "ERROR: Something is already listening on port 8080."
    echo "Stop any existing api-bn containers first: docker rm -f api-bn"
    exit 1
fi

# ─── Build ───
echo "=== Building image ==="
IMAGE_NAME="$IMAGE_NAME" IMAGE_TAG="$IMAGE_TAG" "${SCRIPT_DIR}/build.sh"

# ─── Run ───
echo "=== Starting container ==="
docker run -d --name "$CONTAINER_NAME" --network host "${IMAGE_NAME}:${IMAGE_TAG}"

# ─── Wait for readiness ───
echo "=== Waiting for boundary node to become ready (up to ${MAX_WAIT}s) ==="
WAITED=0
while true; do
    # Check container is still running
    if ! docker inspect --format='{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null | grep -q true; then
        echo "FAIL: Container exited unexpectedly."
        docker logs "$CONTAINER_NAME" 2>&1 | tail -30
        exit 1
    fi

    # Check if the boundary node is healthy via the Prometheus metric
    if curl -sf http://localhost:9090/metrics 2>/dev/null | grep -q 'ic_boundary_healthy 1'; then
        echo "Boundary node is healthy after ${WAITED}s."
        break
    fi

    if [ "$WAITED" -ge "$MAX_WAIT" ]; then
        echo "FAIL: Boundary node did not become healthy within ${MAX_WAIT}s."
        docker logs "$CONTAINER_NAME" 2>&1 | tail -30
        exit 1
    fi

    sleep 5
    WAITED=$((WAITED + 5))
    if [ $((WAITED % 30)) -eq 0 ]; then
        echo "  Still waiting... (${WAITED}s)"
    fi
done

# ─── Test canister query ───
echo "=== Testing canister query ==="
RESULT=$(dfx canister --network http://localhost:8080 call ryjl3-tyaaa-aaaaa-aaaba-cai name --query 2>&1)

if echo "$RESULT" | grep -q "Internet Computer"; then
    echo "PASS: $RESULT"
    exit 0
else
    echo "FAIL: Unexpected response: $RESULT"
    exit 1
fi
