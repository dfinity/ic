#!/usr/bin/env bash

set -xeuo pipefail

is_ci_job() {
    [ "${CI_JOB_ID:-}" != "" ] && [ "${CI_JOB_NAME:-}" != "" ]
}

BUILD_OUT=${1:-"build-out/update-img${BUILD_EXTRA_SUFFIX}"}
UPLOAD_TARGET="guest-os/update-img${BUILD_EXTRA_SUFFIX}"
REPO_ROOT=$(git rev-parse --show-toplevel)
VERSION=$(git rev-parse HEAD)
export VERSION
echo "Build ID: ${VERSION}"

if ! ls "$REPO_ROOT"/artifacts/release/*.gz 2>/dev/null; then
    echo "Pulling binaries from S3"
    "$REPO_ROOT"/gitlab-ci/src/artifacts/rclone_download.py \
        --git-rev="${VERSION}" --remote-path="release" \
        --out="artifacts/release"
fi

ls -lah /var/run/docker.sock
groups

for f in replica orchestrator canister_sandbox sandbox_launcher vsock_agent state-tool ic-consensus-pool-util ic-crypto-csp ic-regedit ic-btc-adapter ic-canister-http-adapter; do
    gunzip -c -d artifacts/release/$f.gz >artifacts/release/$f
done

# if we are building the malicious image, use malicious replica version
if [[ "${BUILD_EXTRA_SUFFIX}" =~ "malicious" ]]; then
    gunzip -c -d artifacts/release-malicious/replica.gz >artifacts/release/replica
    chmod +x artifacts/release/replica
fi

cd ic-os/guestos
mkdir -p "${BUILD_OUT}"

# shellcheck disable=SC2086  # Expanding BUILD_EXTRA_ARGS into multiple parameters
buildevents cmd "${ROOT_PIPELINE_ID}" "${CI_JOB_ID}" build-disk-upgrade-img -- \
    ./scripts/build-update-image.sh -o "${BUILD_OUT}"/update-img.tar.gz -v "${VERSION}" -x ../../artifacts/release ${BUILD_EXTRA_ARGS}

# Create a second upgrade image with different version number to ease testing with self upgrades
# shellcheck disable=SC2086  # Expanding BUILD_EXTRA_ARGS into multiple parameters
buildevents cmd "${ROOT_PIPELINE_ID}" "${CI_JOB_ID}" build-disk-upgrade-img -- \
    ./scripts/build-update-image.sh -o "${BUILD_OUT}"/update-img-test.tar.gz -v "${VERSION}-test" -x ../../artifacts/release ${BUILD_EXTRA_ARGS}

ls -lah "${BUILD_OUT}"

if is_ci_job; then
    "$REPO_ROOT"/gitlab-ci/src/artifacts/openssl-sign.sh "${BUILD_OUT}"

    buildevents cmd "${ROOT_PIPELINE_ID}" "${CI_JOB_ID}" rclone -- \
        "$REPO_ROOT"/gitlab-ci/src/artifacts/rclone_upload.py --version="${VERSION}" "${BUILD_OUT}" "${UPLOAD_TARGET}"
fi
