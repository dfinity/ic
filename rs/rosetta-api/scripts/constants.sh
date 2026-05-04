#!/usr/bin/env bash

export SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
export LEDGER_CANISTER_ID="ryjl3-tyaaa-aaaaa-aaaba-cai"
export ARCHIVE_CANISTER_ID="qjdve-lqaaa-aaaaa-aaaeq-cai"
export LEDGER_DID="$SCRIPT_DIR/../../ledger_suite/icp/ledger.did"
export TMP_DIR="$SCRIPT_DIR/tmp" # need a persistent directory from within dev container
export HOME="${DFX_HOME:-$HOME}"
export NNS_TEST_ID="nns_test_user_dfx_identity"
