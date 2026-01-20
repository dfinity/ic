#!/usr/bin/env bash

set -eEuo pipefail

usage() {
    echo "Build ic-build docker image."
    echo " "
    echo "Options:"
    echo "-h, --help   show brief help"
    echo "--container-cmd <cmd>    specify container build command (e.g., 'docker', 'podman', or 'sudo podman';"
    echo "                         otherwise will choose based on detected environment)"
    echo ""
    echo "Advanced:"
    echo "  Set the DOCKER_BUILD_ARGS environment variable to pass additional"
    echo "  arguments to the docker build command (e.g., export DOCKER_BUILD_ARGS=\"--no-cache\")."
}

CONTAINER_CMD=() # Default: empty, will auto-detect later

while test $# -gt 0; do
    case "$1" in
        -h | --help)
            usage >&2
            exit 0
            ;;
        --container-cmd)
            shift
            if [ $# -eq 0 ]; then
                echo "Error: --container-cmd requires an argument" >&2
                usage >&2
                exit 1
            fi
            # Split the argument into an array (supports "sudo podman")
            read -ra CONTAINER_CMD <<<"$1"
            shift
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

if [ ${#CONTAINER_CMD[@]} -gt 0 ]; then
    echo "Using user-specified container command: ${CONTAINER_CMD[*]}"
    ARGS=()
# Detect if we're running in a Devenv environment
elif [ -d /var/lib/cloud/instance ] && findmnt /hoststorage >/dev/null; then
    echo "Detected Devenv environment, using hoststorage for podman root."
    CONTAINER_CMD=(sudo podman)
    ARGS=(--root /hoststorage/podman-root)
else
    CONTAINER_CMD=(docker)
    ARGS=()
fi

echo "Building ic-build:$DOCKER_IMG_TAG"

DOCKER_BUILDKIT=1 "${CONTAINER_CMD[@]}" "${ARGS[@]}" build "${BUILD_ARGS[@]}" \
    -t ic-build:"$DOCKER_IMG_TAG" \
    -t ghcr.io/dfinity/ic-build:"$DOCKER_IMG_TAG" \
    -t ghcr.io/dfinity/ic-build:latest \
    -f ci/container/Dockerfile .

popd
