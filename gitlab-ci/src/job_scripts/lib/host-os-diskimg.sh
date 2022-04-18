#!/usr/bin/env bash
#
# Script for host-os-diskimg CI job
#

set -euo pipefail

BUILD_OUT=${1:-"build-out/disk-img"}
BUILD_TMP=${2:-"build-tmp"}
UPLOAD_TARGET=${3:-"host-os/disk-img"}
VERSION=${4:-$(git rev-parse --verify HEAD)}

ROOT_DIR=$(git rev-parse --show-toplevel)
ls -lah /var/run/docker.sock
groups

cd "$ROOT_DIR"/ic-os/hostos || exit 1

mkdir -p "$BUILD_OUT" "$BUILD_TMP"
echo "$VERSION" >"${BUILD_TMP}/version.txt"

if [ -z "$CI_JOB_ID" ]; then
    ./build.sh -v "$VERSION" "$BUILD_EXTRA_ARGS"
    tar xzf disk-img.tar.gz -C "$BUILD_TMP"
    tar --sort=name --owner=root:0 --group=root:0 --mtime='UTC 2020-01-01' --sparse \
        -cvzf "${BUILD_OUT}/host-disk-img.tar.gz" -C "$BUILD_TMP" disk.img version.txt
    ls -lah "$BUILD_TMP"
else
    buildevents cmd "${ROOT_PIPELINE_ID}" "${CI_JOB_ID}" build-disk-img -- \
        ./build.sh -v "$VERSION" "$BUILD_EXTRA_ARGS"
    buildevents cmd "$ROOT_PIPELINE_ID" "$CI_JOB_ID" move-build -- \
        tar xzf disk-img.tar.gz -C "$BUILD_TMP"
    buildevents cmd "$ROOT_PIPELINE_ID" "$CI_JOB_ID" tar-build-out -- \
        tar --sort=name --owner=root:0 --group=root:0 --mtime='UTC 2020-01-01' --sparse \
        -cvzf "${BUILD_OUT}/host-disk-img.tar.gz" -C "$BUILD_TMP" disk.img version.txt
    ls -lah "$BUILD_TMP"

    "$ROOT_DIR"/gitlab-ci/src/artifacts/openssl-sign.sh "$BUILD_OUT"

    if [ "$CI_JOB_NAME" != "docker-build-all" ]; then
        buildevents cmd "$ROOT_PIPELINE_ID" "$CI_JOB_ID" rclone -- \
            "$ROOT_DIR"/gitlab-ci/src/artifacts/rclone_upload.py "$BUILD_OUT" "$UPLOAD_TARGET"
    fi
fi
