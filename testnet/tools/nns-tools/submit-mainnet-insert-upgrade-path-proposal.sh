#!/bin/bash
set -euo pipefail

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

    TARGET_SNS_GOVERNANCE_CANISTER=$(proposal_header_field_value $PROPOSAL_FILE "Target SNS Governance Canister:")

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
        --sns-governance-canister-id=$TARGET_SNS_GOVERNANCE_CANISTER
        --summary-file=$PROPOSAL_FILE
        --proposer=$NEURON_ID
    )
    for V in $(extract_versions_to_publish $PROPOSAL_FILE); do
        cmd+=("$V")
    done

    confirm_submit_proposal_command "${cmd[@]}"

    "${cmd[@]}"
}

submit_insert_upgrade_path_proposal_mainnet "$PROPOSAL_FILE" "$NEURON_ID"
