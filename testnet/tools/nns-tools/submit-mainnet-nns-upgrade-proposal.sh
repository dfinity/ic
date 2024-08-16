#!/bin/bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 <PROPOSAL_FILE> <NEURON_ID>
    PROPOSAL_FILE: File with proposal created by ./prepare-mainnet-upgrade-proposal-text.sh (or formatted in that way)
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

submit_nns_upgrade_proposal_mainnet() {
    ensure_variable_set IC_ADMIN

    PROPOSAL_FILE=$1
    NEURON_ID=$2

    CANISTER_ID_IN_PROPOSAL=$(proposal_header_field_value "$PROPOSAL_FILE" "Target canister:")
    VERSION=$(proposal_header_field_value "$PROPOSAL_FILE" "Git Hash:")
    PROPOSAL_SHA=$(proposal_header_field_value "$PROPOSAL_FILE" "New Wasm Hash:")
    CAPITALIZED_CANISTER_NAME=$(nns_upgrade_proposal_canister_raw_name "$PROPOSAL_FILE")
    CANISTER_NAME="$(tr '[:upper:]' '[:lower:]' <<<${CAPITALIZED_CANISTER_NAME:0:1})${CAPITALIZED_CANISTER_NAME:1}"
    CANISTER_ID=$(nns_canister_id "$CANISTER_NAME")

    CANDID_UPGRADE_ARGS=$(extract_candid_upgrade_args "$PROPOSAL_FILE")

    # Functions that exit if error
    validate_nns_version_wasm_sha "$CANISTER_NAME" "$VERSION" "$PROPOSAL_SHA"
    validate_no_todos "$PROPOSAL_FILE"
    validate_nns_canister_id "$CANISTER_NAME" "$CANISTER_ID_IN_PROPOSAL"

    WASM_GZ=$(get_nns_canister_wasm_gz_for_type "$CANISTER_NAME" "$VERSION")
    WASM_SHA=$(sha_256 $WASM_GZ)

    CANDID_ARGS_FILE=""
    if [ ! -z "$CANDID_UPGRADE_ARGS" ]; then
        CANDID_ARGS_FILE=$(encode_candid_args_in_file "$CANDID_UPGRADE_ARGS")
    fi

    echo
    print_green "Proposal Text To Submit"
    cat "$PROPOSAL_FILE"
    print_green "End Proposal Text"
    echo
    print_green "Summary of action:
  You are proposing to update canister $CANISTER_ID ($CAPITALIZED_CANISTER_NAME) to commit $VERSION.
  The WASM hash is $WASM_SHA.

  $(if [ ! -z "$CANDID_ARGS_FILE" ]; then
        echo "Extracted Candid Args:
     '$CANDID_UPGRADE_ARGS'
   which are encoded as
      '$(cat "$CANDID_ARGS_FILE")'
   and decode as:
        '$(cat "$CANDID_ARGS_FILE" | xxd -p | tr -d '\r\n' | xargs didc decode)'"
    fi)
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

    if [ ! -z "$CANDID_ARGS_FILE" ]; then
        cmd+=(--arg=$CANDID_ARGS_FILE)
    fi

    confirm_submit_proposal_command "${cmd[@]}"

    RESPONSE=$("${cmd[@]}")
    echo "$RESPONSE"
    PROPOSAL_ID=$(echo "${RESPONSE}" | grep -o 'proposal [0-9]*' | awk '{print $2}' | tr -d '[:space:]')
    echo "https://dashboard.internetcomputer.org/proposal/${PROPOSAL_ID}"
}

if ! is_variable_set IC_ADMIN; then
    if [ ! -f "$MY_DOWNLOAD_DIR/ic-admin" ]; then
        PREVIOUS_VERSION=$(extract_previous_version "$PROPOSAL_FILE")
        install_binary ic-admin "$PREVIOUS_VERSION" "$MY_DOWNLOAD_DIR"
    fi
    IC_ADMIN=$MY_DOWNLOAD_DIR/ic-admin
fi

submit_nns_upgrade_proposal_mainnet $PROPOSAL_FILE $NEURON_ID
