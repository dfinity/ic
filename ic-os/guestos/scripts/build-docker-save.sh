#!/usr/bin/env bash

# Build docker image in a specific directory and stream its "saved
# image" (layered tar) to stdout.
#
# Arguments to this script are passed verbatim to "docker build".

CI_JOB_NAME=${CI_JOB_NAME:-}
# We implicitly pull dependent image.
ARGS=(--pull)
if [ "$CI_JOB_NAME" == "guest-os-updateimg-build-determinism" ]; then
    # Don't use cache when in CI.
    ARGS+=(--no-cache)
fi

DOCKER_ID=$(
    # Account for two different output formats of docker command:
    # "classic" docker and "buildkit" docker
    echo "docker build ${ARGS[@]} $@" >&2
    docker build "${ARGS[@]}" "$@" 2>&1 | tee /dev/fd/2 | sed -e 's/Successfully built //' -e t -e 's/.*writing image sha256:\([0-9a-f]\{64\}\) .*/\1/' -e t -e d
)

docker save "${DOCKER_ID}"
