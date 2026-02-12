#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IC_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMAGE_NAME="${IMAGE_NAME:-api-boundary-node}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

echo "============================================"
echo "  Building API Boundary Node Docker Image"
echo "============================================"
echo "IC root:  ${IC_ROOT}"
echo "Image:    ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""

echo "[1/4] Building binaries with Bazel..."
cd "${IC_ROOT}"
bazel build \
    //rs/boundary_node/ic_boundary:ic-boundary \
    //rs/orchestrator/registry_replicator:ic-registry-replicator

echo "[2/4] Copying artifacts to build context..."
cp "${IC_ROOT}/bazel-bin/rs/boundary_node/ic_boundary/ic-boundary" "${SCRIPT_DIR}/ic-boundary"
cp "${IC_ROOT}/bazel-bin/rs/orchestrator/registry_replicator/ic-registry-replicator" "${SCRIPT_DIR}/ic-registry-replicator"
cp "${IC_ROOT}/ic-os/components/guestos/share/nns_public_key.pem" "${SCRIPT_DIR}/nns_public_key.pem"

echo "[3/4] Building Docker image..."
cd "${SCRIPT_DIR}"
docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" .

echo "[4/4] Cleaning up build artifacts..."
rm -f "${SCRIPT_DIR}/ic-boundary" \
    "${SCRIPT_DIR}/ic-registry-replicator" \
    "${SCRIPT_DIR}/nns_public_key.pem"

echo ""
echo "============================================"
echo "  Build Complete: ${IMAGE_NAME}:${IMAGE_TAG}"
echo "============================================"
