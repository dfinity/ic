#!/bin/bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 <PROPOSAL_FILE> <NEURON_ID>
    PROPOSAL_FILE: File with proposal created by ./prepare-mainnet-sale-canister-upgrade-proposal-text.sh (or formatted in that way)
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

submit_sale_upgrade_proposal_mainnet() {
    ensure_variable_set IC_ADMIN

    PROPOSAL_FILE=$1
    NEURON_ID=$2

    CANISTER_ID=$(proposal_header_field_value "$PROPOSAL_FILE" "Target canister:")
    VERSION=$(proposal_header_field_value "$PROPOSAL_FILE" "Git Hash:")
    PROPOSAL_SHA=$(proposal_header_field_value "$PROPOSAL_FILE" "New Wasm Hash:")

    # Functions that exit if error
    validate_sns_version_wasm_sha "swap" "$VERSION" "$PROPOSAL_SHA"
    validate_no_todos "$PROPOSAL_FILE"

    WASM_GZ=$(download_sns_canister_wasm_gz_for_type swap "$VERSION")
    WASM_SHA=$(sha_256 "$WASM_GZ")

    echo
    print_green "Proposal Text To Submit"
    cat "$PROPOSAL_FILE"
    print_green "End Proposal Text"
    echo
    print_green "Summary of action:
  You are proposing to update canister $CANISTER_ID (A Sale Canister for an SNS) to commit $VERSION.
  Please verify additionally you are targeting the correct Canister ID for your intended SNS.
  The WASM hash is $WASM_SHA.
    "

    check_or_set_dfx_hsm_pin

    cmd=($IC_ADMIN --use-hsm --slot=0
        --key-id=01 --pin="$DFX_HSM_PIN"
        --nns-url "https://icp-api.io"
        propose-to-change-nns-canister --mode=upgrade
        --canister-id=$CANISTER_ID
        --wasm-module-path=$WASM_GZ
        --wasm-module-sha256=$WASM_SHA
        --summary-file=$PROPOSAL_FILE
        --proposer=$NEURON_ID)

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

submit_sale_upgrade_proposal_mainnet $PROPOSAL_FILE $NEURON_ID
