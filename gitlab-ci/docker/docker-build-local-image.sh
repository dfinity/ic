#!/usr/bin/env bash
# Prepare the Docker container image

set -eEuo pipefail

usage() {
    echo "by default, this script builds the docker base image and ubuntu [non-nix] image"
    echo " "
    echo "options:"
    echo "-h, --help			show brief help"
    echo "-n, --nix			also build the nix-supported Docker image"
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

DOCKER_IMG_VERSION=$(cat "$REPO_ROOT/gitlab-ci/docker/TAG")
SHA1ICBUILD=$("$REPO_ROOT/gitlab-ci/src/docker_image_check/docker_sha.py" Dockerfile)
SHA1ICBUILDSRC=$("$REPO_ROOT/gitlab-ci/src/docker_image_check/docker_sha.py" Dockerfile.src)
SHA1ICBUILDNIX=$("$REPO_ROOT/gitlab-ci/src/docker_image_check/docker_sha.py" Dockerfile.withnix)

USER=$(whoami)
if [ $USER == ubuntu ]; then
    SET_UID=1000
    LATEST="latest"
else
    SET_UID="$(id -u $USER)"
    PREFIX="$USER-$SET_UID"
    DOCKER_IMG_VERSION="$PREFIX-$DOCKER_IMG_VERSION"
    LATEST="$PREFIX-latest"
fi

# Note: This code builds the docker image via a cron job on the trusted builders
# The trusted builders must have the gitlab registry tags on the image. Please
# do not change this code with speaking with Ali Piccioni or Sasa Tomic.

cd "$REPO_ROOT/gitlab-ci/docker"

# Build the dependencies image
DOCKER_BUILDKIT=1 docker build \
    --tag ic-build-src:"$DOCKER_IMG_VERSION" \
    --tag dfinity/ic-build-src:"$DOCKER_IMG_VERSION" \
    --tag dfinity/ic-build-src:"$LATEST" \
    --tag registry.gitlab.com/dfinity-lab/core/docker/ic-build-src:"$DOCKER_IMG_VERSION"-"$SHA1ICBUILDSRC" \
    -f Dockerfile.src .

# Build the container image
DOCKER_BUILDKIT=1 docker build \
    --tag ic-build:"$DOCKER_IMG_VERSION" \
    --tag dfinity/ic-build:"$DOCKER_IMG_VERSION" \
    --tag dfinity/ic-build:"$LATEST" \
    --tag registry.gitlab.com/dfinity-lab/core/docker/ic-build:"$DOCKER_IMG_VERSION"-"$SHA1ICBUILD" \
    --build-arg USER="${USER}" \
    --build-arg UID="${SET_UID}" \
    --build-arg SRC_IMG_PATH="dfinity/ic-build-src:$DOCKER_IMG_VERSION" \
    -f Dockerfile .

# Build the container image with support for nix
if [ "$BUILD_NIX" == "true" ]; then
    DOCKER_BUILDKIT=1 docker build \
        --tag ic-build-nix:"$DOCKER_IMG_VERSION" \
        --tag dfinity/ic-build-nix:"$DOCKER_IMG_VERSION" \
        --tag dfinity/ic-build-nix:"$LATEST" \
        --tag registry.gitlab.com/dfinity-lab/core/docker/ic-build-nix:"$DOCKER_IMG_VERSION"-"$SHA1ICBUILDNIX" \
        --build-arg USER="${USER}" \
        --build-arg UID="${SET_UID}" \
        --build-arg IC_BUILD_IMG_VERSION="${LATEST}" \
        --build-arg SRC_IMG_PATH="dfinity/ic-build-src:$DOCKER_IMG_VERSION" \
        -f Dockerfile.withnix .
fi

cd -
