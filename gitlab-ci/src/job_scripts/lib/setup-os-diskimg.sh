#!/usr/bin/env bash
#
# Script for setup-os-diskimg CI job
#

set -euo pipefail

BUILD_OUT=${1:-"build-out/disk-img"}
BUILD_TMP=${2:-"build-tmp"}
UPLOAD_TARGET=${3:-"setup-os/disk-img"}
VERSION=${4:-$(git rev-parse --verify HEAD)}

ROOT_DIR=$(git rev-parse --show-toplevel)
ls -lah /var/run/docker.sock
groups

cd "$ROOT_DIR"

cd "$ROOT_DIR"/ic-os/setupos
mkdir -p "$BUILD_OUT" "$BUILD_TMP"
echo "$VERSION" >"${BUILD_TMP}/version.txt"

if [ -z "$CI_JOB_ID" ]; then
    ./scripts/build-disk-image.sh "-o=${BUILD_TMP}/disk.img" "-v=$VERSION" "--host-os=./hostos/disk-img/host-disk-img.tar.gz" "--guest-os=./guestos/disk-img/disk-img.tar.gz"
    tar --sort=name --owner=root:0 --group=root:0 --mtime='UTC 2020-01-01' --sparse \
        -cvzf "${BUILD_OUT}/disk-img.tar.gz" -C "$BUILD_TMP" disk.img version.txt
    tar --sort=name --owner=root:0 --group=root:0 --mtime='UTC 2020-01-01' --sparse \
        -cvf "${BUILD_OUT}/disk-img.tar.zst" --use-compress-program="zstd --threads=0 -10" \
        -C "$BUILD_TMP" disk.img version.txt
    ls -lah "$BUILD_TMP"
else
    buildevents cmd "${ROOT_PIPELINE_ID}" "${CI_JOB_ID}" build-disk-img -- \
        ./scripts/build-disk-image.sh "-o=${BUILD_TMP}/disk.img" "-v=$VERSION" "--host-os=./hostos/disk-img/host-disk-img.tar.gz" "--guest-os=./guestos/disk-img/disk-img.tar.gz"
    buildevents cmd "$ROOT_PIPELINE_ID" "$CI_JOB_ID" tar-build-out -- \
        tar --sort=name --owner=root:0 --group=root:0 --mtime='UTC 2020-01-01' --sparse \
        -cvzf "${BUILD_OUT}/disk-img.tar.gz" -C "$BUILD_TMP" disk.img version.txt
    buildevents cmd "$ROOT_PIPELINE_ID" "$CI_JOB_ID" tar-build-out -- \
        tar --sort=name --owner=root:0 --group=root:0 --mtime='UTC 2020-01-01' --sparse \
        -cvf "${BUILD_OUT}/disk-img.tar.zst" --use-compress-program="zstd --threads=0 -10" \
        -C "$BUILD_TMP" disk.img version.txt
    ls -lah "$BUILD_TMP"

    "$ROOT_DIR"/gitlab-ci/src/artifacts/openssl-sign.sh "$BUILD_OUT"
fi
