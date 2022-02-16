#!/usr/bin/env bash

set -euo pipefail

BUILD_OUT=${1:-"build-out/disk-img"}
BUILD_TMP=${2:-"build-tmp"}
UPLOAD_TARGET=${3:-"guest-os/disk-img"}
VERSION=${4:-$(git rev-parse --verify HEAD)}
CDPRNET=${5:-"cdpr05"}

ROOT_DIR=$(git rev-parse --show-toplevel)
ls -lah /var/run/docker.sock
groups

cd "$ROOT_DIR" || exit 1
for f in replica orchestrator canister_sandbox sandbox_launcher vsock_agent state-tool ic-consensus-pool-util ic-crypto-csp ic-regedit ic-btc-adapter; do
    gunzip -c -d artifacts/release/$f.gz >artifacts/release/$f
done

# if we are building the malicious image, use malicious replica version
if [[ "${BUILD_EXTRA_SUFFIX}" =~ "malicious" ]]; then
    gunzip -c -d artifacts/release-malicious/replica.gz >artifacts/release/replica
    chmod +x artifacts/release/replica
fi

cd "$ROOT_DIR"/ic-os/guestos || exit 1
mkdir -p "$BUILD_OUT" "$BUILD_TMP"
echo "$VERSION" >"${BUILD_TMP}/version.txt"

./scripts/build-update-image.sh -o "${BUILD_OUT}/update-img.tar.gz" -v "$VERSION" -x ../../artifacts/release/ "$BUILD_EXTRA_ARGS"
ls -lah "$BUILD_OUT"
