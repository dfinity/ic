#!/usr/bin/env bash

set -eEo pipefail

usage() {
    echo "Build ic-build docker image."
    echo " "
    echo "Options:"
    echo "-h, --help   show brief help"
    echo "--ci              build the CI image"
    echo "--dev             build the devenv image"
    echo "--container-cmd <cmd>    specify container build command (e.g., 'docker', 'podman', or 'sudo podman';"
    echo "                         otherwise will choose based on detected environment)"
    echo "--build-args <args>      specify additional build arguments for docker build command (default --rm=true)"
    echo ""
}

CONTAINER_CMD=() # Default: empty, will auto-detect later
BUILD_ARGS=("--rm=true")

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

if [ "${CONTAINER_CMD[*]:-}" ]; then
    echo "Using user-specified container command: ${CONTAINER_CMD[*]}"
    ARGS=()
# Detect if we're running in a Devenv environment
elif [ -d /var/lib/cloud/instance ] && findmnt /hoststorage >/dev/null; then
    echo "Detected Devenv environment, using hoststorage for podman root."
    CONTAINER_CMD=(sudo podman --root /hoststorage/podman-root)
else
    CONTAINER_CMD=(docker)
fi

DOCKER_BUILDKIT=1 "${CONTAINER_CMD[@]}" build "${BUILD_ARGS[@]}" \
    --target "$BUILD_TARGET" \
    -t $IMAGE_NAME:"$DOCKER_IMG_TAG" \
    -t ghcr.io/dfinity/$IMAGE_NAME:"$DOCKER_IMG_TAG" \
    -t ghcr.io/dfinity/$IMAGE_NAME:latest \
    -f ci/container/Dockerfile .

popd
