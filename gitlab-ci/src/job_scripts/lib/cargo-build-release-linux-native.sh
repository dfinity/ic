#!/usr/bin/env bash
#
# Script for cargo-build-release-linux-native CI job
#
#  - Builds rs/
#  - Collects builds binaries and puts them to artifacts/release
#
set -exuo pipefail

ROOT_DIR=$(git rev-parse --show-toplevel)
CI_PROJECT_DIR=${CI_PROJECT_DIR:-$ROOT_DIR}
CARGO_BUILD_TARGET=x86_64-unknown-linux-gnu
CI_JOB_NAME=${CI_JOB_NAME:-""}
export CI_PROJECT_DIR
export CARGO_BUILD_TARGET

cd "$ROOT_DIR"
bazel run //:collect_binaries -- "$CARGO_TARGET_DIR"/x86_64-unknown-linux-gnu/release 2>&1 \
    | sed --unbuffered 's/\(.*Streaming build results to:.*\)/\o33[92m\1\o33[0m/'
