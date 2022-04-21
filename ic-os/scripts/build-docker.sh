#!/usr/bin/env bash

# Build both bootloader and rootfs docker and save them to docker
# export tar.
#
# Arguments:
# - $1: Directory under which to store the docker output
#
# This script is intended to be used as first part of CI pipeline.

set -euo pipefail

OUT_DIR="$1"
shift

BASE_DIR=$(dirname "${BASH_SOURCE[0]}")/..

mkdir -p $OUT_DIR

docker version

"${BASE_DIR}"/scripts/build-docker-save.sh "${BASE_DIR}"/bootloader >"$OUT_DIR/bootloader.tar"
"${BASE_DIR}"/scripts/build-docker-save.sh "${BASE_DIR}"/rootfs >"$OUT_DIR/rootfs.tar"
