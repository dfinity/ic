#!/usr/bin/env bash

# Build docker image in a specific directory and stream its "saved
# image" (layered tar) to stdout.
#
# Arguments to this script are passed verbatim to "docker build".

echo "docker build ${ARGS[@]} $@" >&2
docker build --iidfile iidfile "${ARGS[@]}" "$@" >&2
IMAGE_ID=$(cat iidfile | cut -d':' -f2)

docker save "$IMAGE_ID" -o "$IMAGE_ID.tar"
cat "$IMAGE_ID.tar"
