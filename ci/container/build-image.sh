#!/usr/bin/env bash

set -eEuo pipefail

usage() {
    echo "Build ic-build docker image."
    echo " "
    echo "Options:"
    echo "-h, --help   show brief help"
    echo "-b, --bazel  only build bazel image"
    exit 0
}

while test $# -gt 0; do
    case "$1" in
        -h | --help) usage ;;
        -b* | --bazel*)
            ONLY_BAZEL=true
            shift
            ;;
    esac
done

REPO_ROOT="$(git rev-parse --show-toplevel)"
DOCKER_IMG_TAG=$("$REPO_ROOT"/gitlab-ci/container/get-image-tag.sh)

pushd "$REPO_ROOT"

# we can pass '--no-cache' from env
BUILD_ARGS=("${DOCKER_BUILD_ARGS:---rm=true}")
RUST_VERSION=$(grep channel rust-toolchain.toml | sed -e 's/.*=//' | tr -d '"')

if findmnt /hoststorage >/dev/null; then
    ARGS=(--root /hoststorage/podman-root)
else
    ARGS=()
fi

DOCKER_BUILDKIT=1 docker "${ARGS[@]}" build "${BUILD_ARGS[@]}" \
    -t ic-build:"$DOCKER_IMG_TAG" \
    -t docker.io/dfinity/ic-build:"$DOCKER_IMG_TAG" \
    -t docker.io/dfinity/ic-build:latest \
    -t ghcr.io/dfinity/ic-build:"$DOCKER_IMG_TAG" \
    --build-arg RUST_VERSION="$RUST_VERSION" \
    -f gitlab-ci/container/Dockerfile .

if [ "${ONLY_BAZEL:-false}" == "true" ]; then
    popd
    exit 0
fi

popd
