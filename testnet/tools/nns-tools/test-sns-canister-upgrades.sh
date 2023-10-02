#!/bin/bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 <VERSION> <SNS_CANISTER_TYPE> (<SNS_CANISTER_TYPE>...)
  VERSION: Version to test (generally git hash, could be build id.  Green checkmarks on gitlab commit list have assets)
  SNS_CANISTER_TYPE: Human readable SNS canister name (root, governance, ledger, swap, archive, index)


  NOTE: Both NNS_URL and NEURON_ID must be set as environment variables.
    Using \"source \$YOUR_WORKING_DIRECTORY/output_vars_nns_state_deployment.sh\" will give you the needed
    variables in your shell.

  This script will test upgrading the canisters to a particular version, and will test doing so
    in all possible permutations of the upgrades.
  "
    exit 1
}

if [ $# -lt 2 ]; then
    help
fi
VERSION=$1
shift
CANISTERS="${@}"

ensure_variable_set IDL2JSON
ensure_variable_set SNS_QUILL
ensure_variable_set IC_ADMIN

ensure_variable_set NNS_URL
ensure_variable_set SUBNET_URL
ensure_variable_set NEURON_ID
ensure_variable_set WALLET_CANISTER

PEM="$NNS_TOOLS_DIR/test_user.pem"

# Install the sns binary corresponding to the latest NNS Governance canister
SNS_CLI_VERSION=$(nns_canister_git_version "${NNS_URL}" "governance")
install_binary sns "$SNS_CLI_VERSION" "$MY_DOWNLOAD_DIR"

PERMUTATIONS=$(python3 \
    -c 'import itertools,sys;print(*[" ".join(p) for p in itertools.permutations(sys.argv[1:])],sep="\n")' \
    $CANISTERS)

LOG_FILE=$(mktemp)

sns_canister_id_for_sns_canister_type() {
    local SNS_CANISTER_TYPE=$1
    cat $PWD/sns_canister_ids.json | jq -r ".${SNS_CANISTER_TYPE}_canister_id"
}

upgrade_swap() {
    NNS_URL=$1
    NEURON_ID=$2
    PEM=$3
    CANISTER_ID=$4
    VERSION_OR_WASM=$5

    WASM_FILE=$([ -f "$VERSION_OR_WASM" ] && echo "$VERSION_OR_WASM" || download_sns_canister_wasm_gz_for_type swap "$VERSION")

    propose_upgrade_canister_wasm_file_pem "$NNS_URL" "$NEURON_ID" "$PEM" "$CANISTER_ID" "$WASM_FILE"
}

upgrade_sns() {
    NNS_URL=$1
    SUBNET_URL=$2
    NEURON_ID=$3
    PEM=$4
    CANISTER_NAME=$5
    VERSION_OR_WASM=$6
    LOG_FILE=$7
    SWAP_CANISTER_ID=$8
    GOV_CANISTER_ID=$9

    # For swap testing, we want to do the NNS upgrade
    if [[ $CANISTER_NAME = "swap" ]]; then
        echo "Submitting upgrade proposal to NNS Governance for Swap" | tee -a "$LOG_FILE"
        upgrade_swap "$NNS_URL" "$NEURON_ID" "$PEM" "$SWAP_CANISTER_ID" "$VERSION_OR_WASM"
    fi

    # SNS upgrade proposal - needed even if swap was upgraded
    echo "Submitting upgrade proposal to $GOV_CANISTER_ID" | tee -a "$LOG_FILE"
    sns_upgrade_to_next_version "$SUBNET_URL" "$PEM" "$GOV_CANISTER_ID" 0
}

echo "$PERMUTATIONS" | while read -r ORDERING; do

    echo "Reset versions to mainnet"
    reset_sns_w_versions_to_mainnet "$NNS_URL" "$NEURON_ID"
    # propose new SNS
    echo "Proposing new SNS!" | tee -a "${LOG_FILE}"

    if ! propose_new_sns "$NNS_URL" "$NEURON_ID"; then
        print_red "Failed to create a new SNS via 1-proposal initialization"
        exit 1
    fi
    # get the canister ID for the new SNS Governance
    echo "Proposed new SNS" | tee -a $LOG_FILE

    # Get the latest SNS canisters and create the sns_canister_ids.json file
    SNS=$(list_deployed_snses "${NNS_URL}" | $IDL2JSON | jq '.instances[-1]')
    echo "$SNS" | jq '{
            governance_canister_id: .governance_canister_id[0],
            ledger_canister_id: .ledger_canister_id[0],
            root_canister_id: .root_canister_id[0],
            swap_canister_id: .swap_canister_id[0],
            index_canister_id: .index_canister_id[0]
        }' >$PWD/sns_canister_ids.json

    echo "${SNS}" | tee -a $LOG_FILE

    GOV_CANISTER_ID=$(sns_canister_id_for_sns_canister_type governance)
    ROOT_CANISTER_ID=$(sns_canister_id_for_sns_canister_type root)
    SWAP_CANISTER_ID=$(sns_canister_id_for_sns_canister_type swap)
    LEDGER_CANISTER_ID=$(sns_canister_id_for_sns_canister_type ledger)

    # Participate in Swap to commit it (this spawns the archive canister)
    sns_quill_participate_in_sale "${NNS_URL}" "${SUBNET_URL}" "${PEM}" "${ROOT_CANISTER_ID}" 30000

    # Wait for finalization to complete
    if ! wait_for_sns_governance_to_be_in_normal_mode "${SUBNET_URL}" "${GOV_CANISTER_ID}"; then
        print_red "Swap finalization failed, cannot continue with upgrade testing"
        exit 1
    fi

    # Add the archive canister to sns_canister_ids.json for use during upgrade testing
    ARCHIVE_CANISTER_ID=$(sns_get_archive "${SUBNET_URL}" "${LEDGER_CANISTER_ID}")
    add_archive_to_sns_canister_ids "$PWD/sns_canister_ids.json" "${ARCHIVE_CANISTER_ID}"

    # Assert that all canisters have the mainnet hashes so our test is legitimate
    canister_has_hash_installed $SUBNET_URL \
        $(sns_canister_id_for_sns_canister_type governance) $(sns_mainnet_latest_wasm_hash governance)
    canister_has_hash_installed $SUBNET_URL \
        $(sns_canister_id_for_sns_canister_type root) $(sns_mainnet_latest_wasm_hash root)
    canister_has_hash_installed $SUBNET_URL \
        $(sns_canister_id_for_sns_canister_type ledger) $(sns_mainnet_latest_wasm_hash ledger)
    canister_has_hash_installed $SUBNET_URL \
        $(sns_canister_id_for_sns_canister_type index) $(sns_mainnet_latest_wasm_hash index)
    canister_has_hash_installed $SUBNET_URL \
        $(sns_canister_id_for_sns_canister_type swap) $(sns_mainnet_latest_wasm_hash swap)
    canister_has_hash_installed $SUBNET_URL \
        $(sns_canister_id_for_sns_canister_type archive) $(sns_mainnet_latest_wasm_hash archive)

    # Archive is not going to be available for testing in this way because it is spawned after a certain
    # threshold of activity

    for CANISTER in $ORDERING; do
        echo "Uploading $CANISTER WASM to SNS-W" | tee -a $LOG_FILE
        upload_canister_git_version_to_sns_wasm "$NNS_URL" "$NEURON_ID" \
            "$PEM" "$CANISTER" "$VERSION"

        upgrade_sns "$NNS_URL" "$SUBNET_URL" "$NEURON_ID" "$PEM" \
            "$CANISTER" "$VERSION" "$LOG_FILE" "$SWAP_CANISTER_ID" "$GOV_CANISTER_ID"

        echo "Waiting for upgrade..." | tee -a $LOG_FILE
        if ! wait_for_sns_canister_has_version "$SUBNET_URL" \
            $(sns_canister_id_for_sns_canister_type $CANISTER) "$CANISTER" "$VERSION"; then
            print_red "Failed upgrade for '$ORDERING' on step upgrading '$CANISTER'" | tee -a $LOG_FILE
            break
        fi

    done

    for CANISTER in $ORDERING; do

        echo "Uploading ungzipped $CANISTER WASM to SNS-W" | tee -a $LOG_FILE
        WASM_GZ_FILE=$(download_sns_canister_wasm_gz_for_type "$CANISTER" "$VERSION")

        ORIGINAL_HASH=$(sha_256 "$WASM_GZ_FILE")
        UNZIPPED=$(ungzip "$WASM_GZ_FILE")
        NEW_HASH=$(sha_256 "$UNZIPPED")
        if [ "$NEW_HASH" == "$ORIGINAL_HASH" ]; then
            print_red "Hashes were the same, aborting rest of test..."
            break
        fi
        upload_wasm_to_sns_wasm "$NNS_URL" "$NEURON_ID" \
            "$PEM" "$CANISTER" "$UNZIPPED"

        upgrade_sns "$NNS_URL" "$SUBNET_URL" "$NEURON_ID" "$PEM" \
            "$CANISTER" "$UNZIPPED" "$LOG_FILE" "$SWAP_CANISTER_ID" "$GOV_CANISTER_ID"

        if ! wait_for_canister_has_file_contents "$SUBNET_URL" \
            $(sns_canister_id_for_sns_canister_type $CANISTER) "$UNZIPPED"; then
            print_red "Subsequent upgrade failed."
            print_red "Failed upgrade for '$ORDERING' on step upgrading '$CANISTER'" | tee -a $LOG_FILE
            break
        fi
    done

    # After all the upgrade testing is done, check that a new SNS could still be deployed
    # propose new SNS
    echo "Proposing new SNS!" | tee -a "${LOG_FILE}"

    if ! propose_new_sns "$NNS_URL" "$NEURON_ID"; then
        print_red "Failed to create a new SNS via 1-proposal initialization"
        exit 1
    fi
    # get the canister ID for the new SNS Governance
    echo "Proposed new SNS" | tee -a $LOG_FILE

    # Get the latest SNS canisters and create the sns_canister_ids.json file
    SNS=$(list_deployed_snses "${NNS_URL}" | $IDL2JSON | jq '.instances[-1]')
    echo "$SNS" | jq '{
            governance_canister_id: .governance_canister_id[0],
            ledger_canister_id: .ledger_canister_id[0],
            root_canister_id: .root_canister_id[0],
            swap_canister_id: .swap_canister_id[0],
            index_canister_id: .index_canister_id[0]
        }' >$PWD/sns_canister_ids.json

    echo "${SNS}" | tee -a $LOG_FILE

    print_green "Finished testing 'Upgrade Order: $ORDERING' but check for failures" | tee -a $LOG_FILE
    # Log finished with ordering

done

print_green Testing finished.
echo Test logs recorded in: "$LOG_FILE"
