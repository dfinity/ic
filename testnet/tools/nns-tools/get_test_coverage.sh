#!/bin/bash

# A tool for generating test coverage report for SNS/NNS canisters.
# It uses https://github.com/taiki-e/cargo-llvm-cov

set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/../lib.sh"

print_usage() {
    echo >&2 "USAGE: $0 <sns|nns> <canister-name>"
}

get_filter_regex() {
    local canister_name=$1
    case $canister_name in
        governance)
            echo '(crypto|protobuf|types|rosetta|rust_canisters|utils|nervous_system|canister_client|phantom_newtype|test_utilities|artifact_|registry|bitcoin|interfaces|nns|consensus|execution_|canister_|embedders|canonical_|config|sys|sns/root|sns/init|state_|xnet|replicated_|monitoring|replica|p2p|messaging|prep|transport|ingress|universal_|cycles_|memory_|tree_|validator|certification|sns/swap)'
            ;;
        swap)
            echo '(crypto|protobuf|types|rosetta|rust_canisters|sns/governance|utils|nervous_system|canister_client|phantom_newtype|test_utilities)'
            ;;
        root)
            echo '(bitcoin|crypto|nervous_|phantom_|protobuf|rosetta|rust_|sns/governance|sns/swap|types|test_|utils/)'
            ;;
        *)
            error "Unsupported canister $canister_name"
            ;;
    esac
}

if [ $# -lt 2 ]; then
    print_usage
    exit 1
fi

NS_INSTANCE="$1"
CANISTER_NAME="$2"
RS_ROOT="$(repo_root)/rs"
CANISTER_DIR="$RS_ROOT/$NS_INSTANCE/$CANISTER_NAME"
FILTER_REGEX="$(get_filter_regex "$CANISTER_NAME")"

info "Generating test coverage report for $NS_INSTANCE-canister $CANISTER_NAME"
cd $CANISTER_DIR
cargo llvm-cov --html --ignore-filename-regex "$FILTER_REGEX"
