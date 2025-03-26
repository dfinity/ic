#!/bin/bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0  <SNS_W_VERSION_INDEX_TO_START> <DIFF> (<DIFF>...)
  SNS_W_VERSION_INDEX_TO_START: The index of the version to start the test from.  -1 is the latest version in mainnet, -2 is the version before that, etc.
  DIFF: A diff from SNS_W_VERSION_INDEX_TO_START, using the same format as prepare-insert-upgrade-path-proposal-text.sh

  Before running this script, you will need to upload the new versions of the SNS canisters to SNS-W so that their hashes are available.

  DIFF should be formatted as {\"governance_wasm_hash\": \"1234defabc\"}
    where the keys are the canister types with '_wasm_hash' and the values are the existing WASM hashes of the wasm to upgrade to.
    See prepare-insert-upgrade-path-proposal-text.sh for more details on what this looks like.

  This script will add the mentioned SNS canister types at the versions.
  "
    exit 1
}

if [ $# -lt 2 ]; then
    help
fi
VERSION_INDEX=$1
shift 1

set_testnet_env_variables

ensure_variable_set IDL2JSON
ensure_variable_set SNS_QUILL
ensure_variable_set IC_ADMIN

ensure_variable_set NNS_URL
ensure_variable_set NEURON_ID
ensure_variable_set WALLET_CANISTER
ensure_variable_set PEM

# Install the sns binary corresponding to the latest NNS Governance canister
SNS_CLI_VERSION=$(nns_canister_git_version "${NNS_URL}" "governance")
install_binary sns "$SNS_CLI_VERSION" "$MY_DOWNLOAD_DIR"

LOG_FILE=$(mktemp)
echo "Log file is $LOG_FILE"

upgrade_nns_governance_to_test_version "${NNS_URL}" "${NEURON_ID}" "${PEM}"

create_sns_for_upgrade_test "$NNS_URL" "$NEURON_ID" "$PEM" "$VERSION_INDEX"

GOV_CANISTER_ID=$(sns_canister_id_for_sns_canister_type governance)
STARTING_POINT=$(sns_mainnet_canister_wasm_hash_versions "$VERSION_INDEX")
DIFFS=()
for ((c = 1; c <= $#; c++)); do
    DIFFS+=("${!c}")
done

insert_sns_wasm_upgrade_paths_for_all_snses "$NNS_URL" "$NEURON_ID" "$PEM" "$STARTING_POINT" "${DIFFS[@]}"

for DIFF in "${DIFFS[@]}"; do
    CANISTER=$(echo "$DIFF" | jq -r 'keys[0] | sub("_wasm_hash"; "")')
    HASH=$(echo "$DIFF" | jq -r ".[\"${CANISTER}_wasm_hash\"]")

    if [ "$CANISTER" == "swap" ]; then
        print_red >&2 "We don't support swap yet in this test"
        exit 1
    fi

    sns_upgrade_to_next_version "$NNS_URL" "$PEM" "$GOV_CANISTER_ID" 0

    echo "Waiting for upgrade..." | tee -a $LOG_FILE
    if ! wait_for_sns_canister_has_hash "$NNS_URL" \
        $(sns_canister_id_for_sns_canister_type $CANISTER) "$HASH"; then
        print_red "Failed upgrade on step upgrading '$CANISTER' to '$HASH'" | tee -a $LOG_FILE
        break
    fi

done

print_green Testing finished.
echo Test logs recorded in: "$LOG_FILE"
