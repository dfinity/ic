#!/usr/bin/env bash

# Build docker image in a specific directory and stream its "saved
# image" (layered tar) to stdout.
#
# Arguments to this script are passed verbatim to "docker build".

DOCKER_ID=$(
    # Account for two different output formats of docker command:
    # "classic" docker and "buildkit" docker
    echo "docker build $@" >&2
    docker build "$@" 2>&1 | tee >(cat 1>&2) | sed -e 's/Successfully built //' -e t -e 's/.*writing image sha256:\([0-9a-f]\{64\}\) .*/\1/' -e t -e d
)

docker save "${DOCKER_ID}"
