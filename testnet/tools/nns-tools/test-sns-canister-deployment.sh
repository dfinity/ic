#!/bin/bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 <VERSION> <SNS_CANISTER_TYPE> (<SNS_CANISTER_TYPE>...)
  VERSION: Version to test (generally git hash, could be build id.  Green checkmarks on GitHub commit list have assets)
  SNS_CANISTER_TYPE: Human readable SNS canister name (root, governance, ledger, swap, archive, index)

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

set_testnet_env_variables

ensure_variable_set IDL2JSON
ensure_variable_set SNS_QUILL
ensure_variable_set IC_ADMIN

ensure_variable_set NNS_URL
ensure_variable_set NEURON_ID
ensure_variable_set WALLET_CANISTER
ensure_variable_set PEM

CONFIG_FILE="${CONFIG_FILE:-"$NNS_TOOLS_DIR"/sns_default_test_init_params_v2.yml}"

echo "Using SNS config file: $CONFIG_FILE"

# Install the sns binary corresponding to the latest NNS Governance canister
SNS_CLI_VERSION=${GIT_COMMIT:-$(nns_canister_git_version "${NNS_URL}" "governance")}
install_binary sns "$SNS_CLI_VERSION" "$MY_DOWNLOAD_DIR"

PERMUTATIONS=$(python3 \
    -c 'import itertools,sys;print(*[" ".join(p) for p in itertools.permutations(sys.argv[1:])],sep="\n")' \
    $CANISTERS)

LOG_FILE=$(mktemp)

upgrade_nns_governance_to_test_version "${NNS_URL}" "${NEURON_ID}" "${PEM}"

echo "$PERMUTATIONS" | while read -r ORDERING; do

    echo "Reset versions to mainnet" | tee -a "${LOG_FILE}"
    reset_sns_w_versions_to_mainnet "$NNS_URL" "$NEURON_ID" "$PEM"

    echo "Set SNS-W to mainnet version"
    MAINNET_VERSION_SNS_W=$(nns_canister_git_version "ic" "sns-wasm")
    propose_upgrade_canister_to_version_pem "$NNS_URL" "$NEURON_ID" "$PEM" "sns-wasm" "$MAINNET_VERSION_SNS_W"
    wait_for_nns_canister_has_version "$NNS_URL" "sns-wasm" "$MAINNET_VERSION_SNS_W"

    echo "Upgrading canister versions to test version"
    for CANISTER in $ORDERING; do
        echo "Uploading $CANISTER WASM to SNS-W" | tee -a $LOG_FILE
        upload_canister_git_version_to_sns_wasm "$NNS_URL" "$NEURON_ID" \
            "$PEM" "$CANISTER" "$VERSION"

    done

    # propose new SNS
    echo "Proposing new SNS!" | tee -a "${LOG_FILE}"

    if ! propose_new_sns "$NNS_URL" "$NEURON_ID" "$CONFIG_FILE"; then
        print_red "Failed to create a new SNS via 1-proposal initialization with mainnet version!"
    else

        # get the canister ID for the new SNS Governance
        echo "Proposed new SNS" | tee -a $LOG_FILE

        echo "Get the latest SNS canisters and create the sns_canister_ids.json file ..." | tee -a $LOG_FILE
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

        echo "Participate in Swap to commit it (this spawns the archive canister) ..." | tee -a $LOG_FILE
        sns_quill_participate_in_swap "${NNS_URL}" "${PEM}" "${ROOT_CANISTER_ID}" 300000

        echo "Wait for finalization to complete ..." | tee -a "${LOG_FILE}"
        if ! wait_for_sns_governance_to_be_in_normal_mode "${NNS_URL}" "${GOV_CANISTER_ID}"; then
            print_red "Swap finalization failed, cannot continue with upgrade testing"
            exit 1
        fi

        echo "Add the archive canister to sns_canister_ids.json for use during upgrade testing ..." | tee -a $LOG_FILE
        ARCHIVE_CANISTER_ID=$(sns_get_archive "${NNS_URL}" "${LEDGER_CANISTER_ID}")
        add_archive_to_sns_canister_ids "$PWD/sns_canister_ids.json" "${ARCHIVE_CANISTER_ID}"
    fi

    # Archive is not going to be available for testing in this way because it is spawned after a certain
    # threshold of activity

    echo "Same but with updated SNS-W"
    propose_upgrade_canister_to_version_pem "$NNS_URL" "$NEURON_ID" "$PEM" "sns-wasm" "$VERSION"
    wait_for_nns_canister_has_version "$NNS_URL" "sns-wasm" "$VERSION"

    # propose new SNS
    echo "Proposing new SNS!" | tee -a "${LOG_FILE}"

    if ! propose_new_sns "$NNS_URL" "$NEURON_ID" "$CONFIG_FILE"; then
        print_red "Failed to create a new SNS via 1-proposal initialization with new version!"
    else

        # get the canister ID for the new SNS Governance
        echo "Proposed new SNS" | tee -a $LOG_FILE

        echo "Get the latest SNS canisters and create the sns_canister_ids.json file ..." | tee -a $LOG_FILE
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

        echo "Participate in Swap to commit it (this spawns the archive canister) ..." | tee -a $LOG_FILE
        sns_quill_participate_in_swap "${NNS_URL}" "${PEM}" "${ROOT_CANISTER_ID}" 300000

        echo "Wait for finalization to complete ..." | tee -a "${LOG_FILE}"
        if ! wait_for_sns_governance_to_be_in_normal_mode "${NNS_URL}" "${GOV_CANISTER_ID}"; then
            print_red "Swap finalization failed, cannot continue with upgrade testing"
            exit 1
        fi

        echo "Add the archive canister to sns_canister_ids.json for use during upgrade testing ..." | tee -a $LOG_FILE
        ARCHIVE_CANISTER_ID=$(sns_get_archive "${NNS_URL}" "${LEDGER_CANISTER_ID}")
        add_archive_to_sns_canister_ids "$PWD/sns_canister_ids.json" "${ARCHIVE_CANISTER_ID}"
    fi

    print_green "Finished testing new SNS Deployment: $ORDERING'.  Check for failures!" | tee -a $LOG_FILE
    # Log finished with ordering
    # We only want to test one permutation because they're equivalent.
    break
done

print_green Testing finished.
echo Test logs recorded in: "$LOG_FILE"
