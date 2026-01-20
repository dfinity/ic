#!/usr/bin/env bash

set -eEuo pipefail

usage() {
    echo "Build ic-build docker image."
    echo " "
    echo "Options:"
    echo "-h, --help   show brief help"
    echo ""
    echo "Advanced:"
    echo "Set the DOCKER_BUILD_ARGS environment variable to pass additional"
    echo "arguments to the docker build command (e.g., export DOCKER_BUILD_ARGS=\"--no-cache\")."
}

while test $# -gt 0; do
    case "$1" in
        -h | --help)
            usage >&2
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;

    esac
done

REPO_ROOT="$(git rev-parse --show-toplevel)"
DOCKER_IMG_TAG=$("$REPO_ROOT"/ci/container/get-image-tag.sh)

pushd "$REPO_ROOT"

BUILD_ARGS=("${DOCKER_BUILD_ARGS:---rm=true}")

# Detect if we're running in a Devenv environment
if [ -d /var/lib/cloud/instance ] && [ findmnt /hoststorage >/dev/null ]; then
    echo "Detected Devenv environment, using hoststorage for podman root."
    DOCKER_CMD="sudo podman"
    ARGS=(--root /hoststorage/podman-root)
else
    DOCKER_CMD="docker"
    ARGS=()
fi

echo "Building ic-build:$DOCKER_IMG_TAG"

DOCKER_BUILDKIT=1 $DOCKER_CMD "${ARGS[@]}" build "${BUILD_ARGS[@]}" \
    -t ic-build:"$DOCKER_IMG_TAG" \
    -t ghcr.io/dfinity/ic-build:"$DOCKER_IMG_TAG" \
    -t ghcr.io/dfinity/ic-build:latest \
    -f ci/container/Dockerfile .

popd
