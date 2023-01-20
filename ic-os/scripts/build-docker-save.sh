#!/usr/bin/env bash

# Build docker image in a specific directory and stream its "saved
# image" (layered tar) to stdout.
#
# Arguments to this script are passed verbatim to "docker build".

TMPDIR=$(mktemp -d)

# We implicitly pull dependent image.
ARGS=(--pull)
if [ "${CI_JOB_NAME:-}" == "build-ic"* ]; then
    # Don't use cache in "build-ic" CI job.
    ARGS+=(--no-cache)
fi

echo "docker build ${ARGS[@]} $@" >&2
docker build --iidfile $TMPDIR/iidfile "${ARGS[@]}" "$@" >&2
IMAGE_ID=$(cat $TMPDIR/iidfile | cut -d':' -f2)

docker save "$IMAGE_ID" -o "$TMPDIR/$IMAGE_ID.tar"
cat "$TMPDIR/$IMAGE_ID.tar"

rm -rf $TMPDIR
