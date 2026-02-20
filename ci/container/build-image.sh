#!/usr/bin/env bash

set -eEo pipefail

usage() {
    echo "Build ic-build or ic-dev docker image."
    echo " "
    echo "Options:"
    echo "-h, --help   show brief help"
    echo "-i | --image <image>     ic-build or ic-dev (default: ic-dev)"
    echo "--container-cmd <cmd>    specify container build command (e.g., 'docker', 'podman', or 'sudo podman';"
    echo "                         otherwise will choose based on detected environment)"
    echo "--build-args <args>      specify additional build arguments for docker build command (default --rm=true)"
    echo ""
}

CONTAINER_CMD=() # Default: empty, will auto-detect later
BUILD_ARGS=("--rm=true")
IMAGE_NAME="ic-dev"

while test $# -gt 0; do
    case "$1" in
        -h | --help)
            usage >&2
            exit 0
            ;;
        -i | --image)
            shift
            if [ $# -eq 0 ]; then
                echo "Error: --image requires an argument" >&2
                usage >&2
                exit 1
            fi
            IMAGE_NAME="$1"
            shift
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
        --build-args)
            shift
            if [ $# -eq 0 ]; then
                echo "Error: --build-args requires an argument" >&2
                usage >&2
                exit 1
            fi
            # Split the argument into an array to support multiple build args
            read -ra BUILD_ARGS <<<"$1"
            shift
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [ $IMAGE_NAME == "ic-build" ]; then
    BUILD_TARGET="build"
elif [ $IMAGE_NAME == "ic-dev" ]; then
    BUILD_TARGET="dev"
else
    echo "Unknown image name: $IMAGE_NAME" >&2
    usage >&2
    exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
DOCKER_IMG_TAG=$("$REPO_ROOT"/ci/container/get-image-tag.sh)

pushd "$REPO_ROOT"

if [ "${CONTAINER_CMD[*]:-}" ]; then
    :
# Detect if we're running in a Devenv environment
elif [ -d /var/lib/cloud/instance ] && findmnt /hoststorage >/dev/null; then
    echo "Detected Devenv environment, using hoststorage for podman root."
    CONTAINER_CMD=(sudo podman --root /hoststorage/podman-root)
else
    CONTAINER_CMD=(docker)
fi

echo "Using container command: ${CONTAINER_CMD[*]}"
echo "Building $IMAGE_NAME:$DOCKER_IMG_TAG"

DOCKER_BUILDKIT=1 "${CONTAINER_CMD[@]}" build "${BUILD_ARGS[@]}" \
    --target "$BUILD_TARGET" \
    -t $IMAGE_NAME:"$DOCKER_IMG_TAG" \
    -t ghcr.io/dfinity/$IMAGE_NAME:"$DOCKER_IMG_TAG" \
    -t ghcr.io/dfinity/$IMAGE_NAME:latest \
    -f ci/container/Dockerfile .

popd
