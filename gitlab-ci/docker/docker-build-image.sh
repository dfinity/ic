#!/usr/bin/env bash

set -eEuo pipefail

usage() {
    echo "Build ic-build[-nix] docker image."
    echo " "
    echo "Options:"
    echo "-h, --help   show brief help"
    echo "-n, --nix    also build the nix-supported Docker image"
    exit 0
}

BUILD_NIX=false
while test $# -gt 0; do
    case "$1" in
        -h | --help) usage ;;
        -n* | --nix*)
            BUILD_NIX=true
            shift
            ;;
    esac
done

REPO_ROOT="$(
    cd "$(dirname "$0")"
    git rev-parse --show-toplevel
)"
cd "$REPO_ROOT"

DOCKER_IMG_TAG=$("$REPO_ROOT"/gitlab-ci/docker/docker-get-image-tag.sh)

USER=$(whoami)
if [ $USER == ubuntu ]; then
    SET_UID=1000
    LATEST="latest"
else
    SET_UID="$(id -u $USER)"
    PREFIX="$USER-$SET_UID"
    DOCKER_IMG_TAG="$PREFIX-$DOCKER_IMG_TAG"
    LATEST="$PREFIX-latest"
fi

pushd "$REPO_ROOT/gitlab-ci/docker"

# we can pass '--no-cache' from env
build_args=("${DOCKER_BUILD_ARGS:---rm=true}")

# build the dependencies image
DOCKER_BUILDKIT=1 docker build "${build_args[@]}" \
    -t ic-build-src:"$DOCKER_IMG_TAG" \
    -t dfinity/ic-build-src:"$DOCKER_IMG_TAG" \
    -t dfinity/ic-build-src:"$LATEST" \
    -t registry.gitlab.com/dfinity-lab/core/docker/ic-build-src:"$DOCKER_IMG_TAG" \
    -f Dockerfile.src .

# build the container image
DOCKER_BUILDKIT=1 docker build "${build_args[@]}" \
    -t ic-build:"$DOCKER_IMG_TAG" \
    -t dfinity/ic-build:"$DOCKER_IMG_TAG" \
    -t dfinity/ic-build:"$LATEST" \
    -t registry.gitlab.com/dfinity-lab/core/docker/ic-build:"$DOCKER_IMG_TAG" \
    --build-arg USER="${USER}" \
    --build-arg UID="${SET_UID}" \
    --build-arg SRC_IMG_PATH="dfinity/ic-build-src:$DOCKER_IMG_TAG" \
    -f Dockerfile .

# build the container image with support for nix
if [ "$BUILD_NIX" == "true" ]; then
    DOCKER_BUILDKIT=1 docker build "${build_args[@]}" \
        -t ic-build-nix:"$DOCKER_IMG_TAG" \
        -t dfinity/ic-build-nix:"$DOCKER_IMG_TAG" \
        -t dfinity/ic-build-nix:"$LATEST" \
        -t registry.gitlab.com/dfinity-lab/core/docker/ic-build-nix:"$DOCKER_IMG_TAG" \
        --build-arg USER="${USER}" \
        --build-arg UID="${SET_UID}" \
        --build-arg IC_BUILD_IMG_VERSION="${LATEST}" \
        --build-arg SRC_IMG_PATH="dfinity/ic-build-src:$DOCKER_IMG_TAG" \
        -f Dockerfile.withnix .
fi

popd
