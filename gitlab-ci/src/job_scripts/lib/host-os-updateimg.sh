#!/usr/bin/env bash

set -euo pipefail

BUILD_OUT=${1:-"build-out/disk-img"}
BUILD_TMP=$(mktemp -d)
UPLOAD_TARGET=${3:-"host-os/disk-img"}
VERSION=${4:-$(git rev-parse --verify HEAD)}
ROOT_PASSWORD=${5:-""}

ROOT_DIR=$(git rev-parse --show-toplevel)
ls -lah /var/run/docker.sock
groups

cd "$ROOT_DIR" || exit 1

cd "$ROOT_DIR"/ic-os/hostos || exit 1
mkdir -p "$BUILD_OUT"
echo "$VERSION" >"${BUILD_TMP}/version.txt"
echo "${VERSION}" >"rootfs/opt/ic/share/version.txt"
echo "${VERSION}" >"rootfs/boot/version.txt"

../scripts/build-docker-save.sh \
    --build-arg ROOT_PASSWORD="${ROOT_PASSWORD}" \
    ./rootfs >$BUILD_TMP/rootfs.tar

../scripts/build-update-image.sh -o "${BUILD_OUT}/host-update-img.tar.gz" -i $BUILD_TMP/rootfs.tar "$BUILD_EXTRA_ARGS"
ls -lah "$BUILD_OUT"
