#!/bin/bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 <PROPOSAL_FILE> <NEURON_ID>
    PROPOSAL_FILE: File with proposal created by ./prepare-publish-sns-wasm-proposal-text.sh (or formatted in that way)
    NEURON_ID: Your mainnet neuron ID, associated with your HSM

  This script will create a proposal on mainnet from a given proposal text.
  It outputs the values for confirmation, and ensures that the target version matches the target hash.
  "
    exit 1
}

if [ $# -ne 2 ]; then
    help
fi

PROPOSAL_FILE=$1
NEURON_ID=$2

extract_versions_to_publish() {
    PROPOSAL_FILE=$1

    cat $PROPOSAL_FILE | sed -n '/^{$/,/^}$/p' | jq -c
}

submit_insert_upgrade_path_proposal_mainnet() {
    ensure_variable_set IC_ADMIN

    PROPOSAL_FILE=$1
    NEURON_ID=$2

    TARGET_SNS_GOVERNANCE_CANISTER=$(proposal_header_field_value $PROPOSAL_FILE "Target SNS Governance Canister(s):")

    validate_no_todos "$PROPOSAL_FILE"

    echo
    print_green "Proposal Text To Submit"
    cat "$PROPOSAL_FILE"
    print_green "End Proposal Text"
    echo
    print_green "Summary of action:
  You are proposing to modify the upgrade paths in SNS-W.
  This will affect $([ "$TARGET_SNS_GOVERNANCE_CANISTER" == "All" ] \
        && echo "All SNSes." \
        || echo "The SNS with Governance Canister ID: $TARGET_SNS_GOVERNANCE_CANISTER.")
  If any of the versions in the proposal are not on the blessed upgrade path, the proposal will fail.
    "

    check_or_set_dfx_hsm_pin

    cmd=($IC_ADMIN --use-hsm --slot=0
        --key-id=01 --pin="$DFX_HSM_PIN"
        --nns-url "https://icp-api.io"
        propose-to-insert-sns-wasm-upgrade-path-entries
        --summary-file=$PROPOSAL_FILE
        --proposer=$NEURON_ID
    )

    if [ "${TARGET_SNS_GOVERNANCE_CANISTER}" == "All" ]; then
        cmd+=("--force-upgrade-main-upgrade-path true")
    else
        cmd+=("--sns-governance-canister-id ${TARGET_SNS_GOVERNANCE_CANISTER}")
    fi

    for V in $(extract_versions_to_publish $PROPOSAL_FILE); do
        cmd+=("$V")
    done

    confirm_submit_proposal_command "${cmd[@]}"

    "${cmd[@]}"
}

if ! is_variable_set IC_ADMIN; then
    if [ ! -f "$MY_DOWNLOAD_DIR/ic-admin" ]; then
        PREVIOUS_VERSION=$(extract_previous_version "$PROPOSAL_FILE")
        install_binary ic-admin "$PREVIOUS_VERSION" "$MY_DOWNLOAD_DIR"
    fi
    IC_ADMIN=$MY_DOWNLOAD_DIR/ic-admin
fi

submit_insert_upgrade_path_proposal_mainnet "$PROPOSAL_FILE" "$NEURON_ID"
