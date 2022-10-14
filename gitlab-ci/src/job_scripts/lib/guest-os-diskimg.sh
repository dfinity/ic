#!/usr/bin/env bash
#
# Script for gutest-os-diskimg CI job
# Inputs:
#  - artifacts/release directory with artifacts
#

set -euo pipefail

BUILD_OUT=${1:-"build-out/disk-img"}
BUILD_MODE=${2:-"dev"}
MALICIOUS_MODE=${3:-}

ROOT_DIR=$(git rev-parse --show-toplevel)
groups

cd "$ROOT_DIR"/ic-os/guestos || exit 1
mkdir -p "$BUILD_OUT"

if [ "$BUILD_MODE" = "dev" ]; then
    ln -sfv "$DEV_ROOT_CA" "$PWD/dev-root-ca.crt"
fi

BUILD_MODE="${BUILD_MODE}${MALICIOUS_MODE}"

# shellcheck disable=SC2086
bazel ${BAZEL_STARTUP_ARGS:-} build ${BAZEL_CI_CONFIG:-} ${BAZEL_EXTRA_ARGS:-} //ic-os/guestos:"$BUILD_MODE"_disk-img.tar_gz //ic-os/guestos:"$BUILD_MODE"_disk-img.tar_zst

cp -fv "$ROOT_DIR"/"$(bazel ${BAZEL_STARTUP_ARGS:-} cquery ${BAZEL_CI_CONFIG:-} ${BAZEL_EXTRA_ARGS:-} --output=files //ic-os/guestos:"$BUILD_MODE"_disk-img.tar_gz)" "$BUILD_OUT"/disk-img.tar.gz
cp -fv "$ROOT_DIR"/"$(bazel ${BAZEL_STARTUP_ARGS:-} cquery ${BAZEL_CI_CONFIG:-} ${BAZEL_EXTRA_ARGS:-} --output=files //ic-os/guestos:"$BUILD_MODE"_disk-img.tar_zst)" "$BUILD_OUT"/disk-img.tar.zst

if [ -n "${CI_JOB_ID:-}" ]; then
    "$ROOT_DIR"/gitlab-ci/src/artifacts/openssl-sign.sh "$BUILD_OUT"
fi

cat "$ROOT_DIR"/"$(bazel ${BAZEL_STARTUP_ARGS:-} cquery ${BAZEL_CI_CONFIG:-} ${BAZEL_EXTRA_ARGS:-} --output=files //ic-os/guestos:"$BUILD_MODE"_version.txt)" >"$ROOT_DIR"/version.txt
