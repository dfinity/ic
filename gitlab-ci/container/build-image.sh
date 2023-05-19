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
USE_BAZEL_VERSION="$(tail -1 $REPO_ROOT/.bazelversion)"
echo "Bazel version: $USE_BAZEL_VERSION"

pushd "$REPO_ROOT"

# we can pass '--no-cache' from env
build_args=("${DOCKER_BUILD_ARGS:---rm=true}")

DOCKER_BUILDKIT=1 docker build "${build_args[@]}" \
    -t ic-build:"$DOCKER_IMG_TAG" \
    -t docker.io/dfinity/ic-build:"$DOCKER_IMG_TAG" \
    -t docker.io/dfinity/ic-build:latest \
    -t registry.gitlab.com/dfinity-lab/core/docker/ic-build:"$DOCKER_IMG_TAG" \
    --build-arg USE_BAZEL_VERSION="${USE_BAZEL_VERSION}" \
    -f gitlab-ci/container/Dockerfile .

if [ "${ONLY_BAZEL:-false}" == "true" ]; then
    popd
    exit 0
fi

# build the dependencies image
DOCKER_BUILDKIT=1 docker build "${build_args[@]}" \
    -t ic-build-src:"$DOCKER_IMG_TAG" \
    -t docker.io/dfinity/ic-build-src:"$DOCKER_IMG_TAG" \
    -t docker.io/dfinity/ic-build-src:latest \
    -t registry.gitlab.com/dfinity-lab/core/docker/ic-build-src:"$DOCKER_IMG_TAG" \
    -f gitlab-ci/container/Dockerfile.src .

# build the container image
DOCKER_BUILDKIT=1 docker build "${build_args[@]}" \
    -t ic-build-legacy:"$DOCKER_IMG_TAG" \
    -t docker.io/dfinity/ic-build-legacy:"$DOCKER_IMG_TAG" \
    -t docker.io/dfinity/ic-build-legacy:latest \
    -t registry.gitlab.com/dfinity-lab/core/docker/ic-build-legacy:"$DOCKER_IMG_TAG" \
    --build-arg SRC_IMG_PATH="dfinity/ic-build-src:$DOCKER_IMG_TAG" \
    --build-arg USE_BAZEL_VERSION="${USE_BAZEL_VERSION}" \
    -f gitlab-ci/container/Dockerfile.legacy .

popd
