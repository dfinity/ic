#!/usr/bin/env bash
set -euo pipefail

readonly PROGNAME="$(basename "$0")"
readonly DFINITY_REPO_PATH="$(
    cd "$(dirname "$0")"
    git rev-parse --show-toplevel
)"

function usage() {
    cat <<EOF

Usage: $PROGNAME [OPTIONS] ROSETTA_NODE_REPO

Copies a subset of the DFINITY repository ($DFINITY_REPO_PATH)
to the ROSETTA_NODE_REPO required to build the ic-rosetta-api executable.

The working copy of ROSETTA_NODE_REPO is wiped out in the process, but the
history is preserved.

OPTIONS:
  -h | --help                print this help message

EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -h | --help)
            usage
            exit
            ;;
        *)
            break
            ;;
    esac
done

if [[ $# -eq 0 ]]; then
    echo "ERROR: ROSETTA_NODE_REPO is not specified"
    usage
    exit
fi

readonly ROSETTA_REPO_PATH="$1"
readonly ROSETTA_TMP_PATH="$(mktemp -d)"

function finally() {
    rm -rf "$ROSETTA_TMP_PATH"
}
trap finally EXIT

cd "$DFINITY_REPO_PATH"/rs

PACKAGES_TO_COPY=(
    base/thread
    canister_client
    certified_vars
    config
    crypto
    interfaces
    monitoring/context_logger
    monitoring/logger
    monitoring/metrics
    nns/constants
    nns/common
    nns/governance
    phantom_newtype
    protobuf
    registry/canister
    registry/client
    registry/common
    registry/keys
    registry/provisional_whitelist
    registry/routing_table
    registry/subnet_features
    registry/subnet_type
    registry/transport
    rosetta-api
    rust_canisters/dfn_core
    rust_canisters/dfn_candid
    rust_canisters/dfn_http
    rust_canisters/dfn_json
    rust_canisters/dfn_macro
    rust_canisters/dfn_protobuf
    rust_canisters/on_wire
    sys
    tree_deserializer
    types/base_types
    types/error_types
    types/ic00_types
    types/types
    types/wasm_types
    utils
)

echo $PROGNAME: copying packages...

for package in "${PACKAGES_TO_COPY[@]}"; do
    mkdir -p "$ROSETTA_TMP_PATH/$(dirname "$package")"
    cp -r "$package" "${ROSETTA_TMP_PATH}/$(dirname "$package")"
done

# NOTE: we do not copy the top-level Cargo.toml file because this
# would require us to copy way too many packages from the DFINITY
# repository just because they are reachable through dev-dependencies.
#
# We're only interested in being able to build rosetta-api, and it
# seems that cargo ignores missing transitive dev-dependencies if
# there is no top-level workspace.
#
# We do copy the Cargo.lock to make builds reproducible.  Having
# unknown packages in Cargo.lock doesn't seem to confuse cargo.
cp Cargo.lock "$ROSETTA_TMP_PATH"/rosetta-api
cp "$DFINITY_REPO_PATH"/licenses/Apache-2.0.txt "$ROSETTA_TMP_PATH"/LICENSE

cd "$ROSETTA_TMP_PATH"

echo $PROGNAME: replacing the contents of $ROSETTA_REPO_PATH...

mkdir -p "$ROSETTA_REPO_PATH"
rm -rf "$ROSETTA_REPO_PATH"/*
cp -r "$ROSETTA_TMP_PATH"/* "$ROSETTA_REPO_PATH"

echo $PROGNAME: done.
