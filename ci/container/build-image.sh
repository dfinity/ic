#!/usr/bin/env bash

set -eEuo pipefail

usage() {
    echo "Build ic-build docker image."
    echo " "
    echo "Options:"
    echo "-h, --help   show brief help"
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

# we can pass '--no-cache' from env
BUILD_ARGS=("${DOCKER_BUILD_ARGS:---rm=true}")

if findmnt /hoststorage >/dev/null; then
    ARGS=(--root /hoststorage/podman-root)
else
    ARGS=()
fi

DOCKER_BUILDKIT=1 podman "${ARGS[@]}" build "${BUILD_ARGS[@]}" \
    -t ic-build:"$DOCKER_IMG_TAG" \
    -f ci/container/Dockerfile .

popd
