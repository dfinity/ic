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

cd "$ROOT_DIR"/rs || exit 1
cargo build --target $CARGO_BUILD_TARGET --release
cargo build --target $CARGO_BUILD_TARGET --release --bin prod-test-driver --bin system-tests --bin ic-rosetta-api
ls -l "$CARGO_TARGET_DIR"/x86_64-unknown-linux-gnu/release

rm -rf artifacts/release
if [ "$CI_JOB_NAME" == "docker-build-all" ] || [ "$CI_JOB_NAME" == "" ]; then
    "$ROOT_DIR"/gitlab-ci/src/artifacts/collect_build_binaries.py artifacts/release
fi
