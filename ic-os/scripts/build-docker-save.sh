#!/usr/bin/env bash

# Build docker image in a specific directory and stream its "saved
# image" (layered tar) to stdout.
#
# Arguments to this script are passed verbatim to "docker build".

# We implicitly pull dependent image.
ARGS=(--pull)
if [ "${CI_JOB_NAME:-}" == "docker-build-ic"* ]; then
    # Don't use cache in "docker-build-ic*" CI job.
    ARGS+=(--no-cache)
fi

echo "docker build ${ARGS[@]} $@" >&2
docker build --iidfile iidfile "${ARGS[@]}" "$@" >&2
IMAGE_ID=$(cat iidfile | cut -d':' -f2)

docker save "$IMAGE_ID" -o "$IMAGE_ID.tar"
cat "$IMAGE_ID.tar"
