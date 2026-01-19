#!/usr/bin/env bash

set -eEuo pipefail

BUILD_TARGET="ci"
IMAGE_NAME="ic-build"

usage() {
    echo "Build ic-build docker image."
    echo " "
    echo "Options:"
    echo "-h, --help        show brief help"
    echo "--ci              build the CI image"
    echo "--dev             build the devenv image"
}

while test $# -gt 0; do
    case "$1" in
        -h | --help)
            usage >&2
            exit 0
            ;;
        --ci)
            BUILD_TARGET="ci"
            IMAGE_NAME="ic-build"
            ;;
        --dev)
            BUILD_TARGET="dev"
            IMAGE_NAME="ic-dev"
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

if [ -z "$BUILD_TARGET" ]; then
    echo "Error: You must specify either --ci or --dev"
    usage >&2
    exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
DOCKER_IMG_TAG=$("$REPO_ROOT"/ci/container/get-image-tag.sh)

pushd "$REPO_ROOT"

# we can pass '--no-cache' from env
BUILD_ARGS=("${DOCKER_BUILD_ARGS:---rm=true}")

if findmnt /hoststorage >/dev/null; then
    ARGS=(--root /hoststorage/podman-root)
else
    ARGS=()
fi

DOCKER_BUILDKIT=1 docker "${ARGS[@]}" build "${BUILD_ARGS[@]}" \
    --target "$BUILD_TARGET" \
    -t "$IMAGE_NAME":"$DOCKER_IMG_TAG" \
    -t ghcr.io/dfinity/"$IMAGE_NAME":"$DOCKER_IMG_TAG" \
    -t ghcr.io/dfinity/"$IMAGE_NAME":latest \
    -f ci/container/Dockerfile .

popd
