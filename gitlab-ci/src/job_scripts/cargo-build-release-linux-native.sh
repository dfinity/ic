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
# we exclude build non-deterministic binaries (job cargo-build-release-linux-native-nd)
# this must match output_files in `rs/Capsule.toml`
cargo build --target $CARGO_BUILD_TARGET --release \
    --bin ic-rosetta-api \
    --bin boundary-node-control-plane \
    --bin canister_sandbox \
    --bin ic-admin \
    --bin ic-consensus-pool-util \
    --bin ic-crypto-csp \
    --bin ic-cup-explorer \
    --bin ic-get-neuron-ids \
    --bin ic-p8s-service-discovery \
    --bin ic-prep \
    --bin ic-regedit \
    --bin ic-replay \
    --bin ic-rosetta-api \
    --bin ic-starter \
    --bin ic-workload-generator \
    --bin orchestrator \
    --bin replica \
    --bin state-tool \
    --bin vsock_agent

ls -l "$CARGO_TARGET_DIR"/x86_64-unknown-linux-gnu/release

rm -rf artifacts/release
if [[ "$CI_JOB_NAME" == "docker-build-ic"* ]] || [ "$CI_JOB_NAME" == "" ]; then
    "$ROOT_DIR"/gitlab-ci/src/artifacts/collect_build_binaries.py artifacts/release
fi
