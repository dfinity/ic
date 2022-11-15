#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$SCRIPT_DIR/functions.sh"

help() {
    echo "
Usage: $0 <PROPOSAL_FILE> <NEURON_ID>
    PROPOSAL_FILE: File with proposal created by ./prepare-mainnet-proposal-text.sh (or formatted in that way)
    NEURON_ID: Your mainnet neuron ID, associated with your HSM

  This script will create a proposal on mainnet from a given proposal text.
  It outputs the values for confirmation, and ensures that the target version matches the target hash.
  "
    exit 1
}

if [ $# -lt 2 ]; then
    help
fi

PROPOSAL_FILE=$1
NEURON_ID=$2

value_from_proposal_text() {
    local FILE=$1
    local FIELD=$2
    cat $FILE | grep "$FIELD" | sed "s/.*$FIELD[[:space:]]*//"
}

check_or_set_dfx_hsm_pin() {
    VALUE=${DFX_HSM_PIN:-}
    if [ -z "$VALUE" ]; then
        echo -n "Enter your HSM_PIN":
        read -s DFX_HSM_PIN
        export DFX_HSM_PIN
        echo
    fi
}

extract_previous_version() {
    local FILE=$1
    cat $FILE | grep "git log" | sed 's/.*\([0-9a-f]\{40\}\)\.\.[0-9a-f]\{40\}.*/\1/'
}

submit_proposal_mainnet() {
    ensure_variable_set IC_ADMIN

    PROPOSAL_FILE=$1
    NEURON_ID=$2

    PROPOSED_CANISTER=$(value_from_proposal_text "$PROPOSAL_FILE" "Target canister:")
    VERSION=$(value_from_proposal_text "$PROPOSAL_FILE" "Git Hash:")
    PROPOSAL_SHA=$(value_from_proposal_text "$PROPOSAL_FILE" "New Wasm Hash:")
    CAPITALIZED_CANISTER_NAME=$(cat $PROPOSAL_FILE | grep "## Proposal to Upgrade the" | cut -d' ' -f6)
    CANISTER_NAME="$(tr '[:upper:]' '[:lower:]' <<<${CAPITALIZED_CANISTER_NAME:0:1})${CAPITALIZED_CANISTER_NAME:1}"
    CANISTER_ID=$(nns_canister_id "$CANISTER_NAME")

    if [ "$PROPOSED_CANISTER" != "$CANISTER_ID" ]; then
        echo "Target canister does not match expected value for named canister in proposal"
        return 1
    fi

    WASM=$(get_nns_canister_wasm_for_type "$CANISTER_NAME" "$VERSION")
    WASM_SHA=$(sha_256 $WASM)

    if [ "$WASM_SHA" != "$PROPOSAL_SHA" ]; then
        echo "SHA256 hash for WASM at proposed version does not match hash stated in proposal"
        exit 1
    fi

    if grep -q -i TODO "$PROPOSAL_FILE"; then
        echo "Cannot submit proposal with 'TODO' items"
        exit 1
    fi

    echo
    print_green "Proposal Text To Submit"
    cat "$PROPOSAL_FILE"
    print_green "End Proposal Text"
    echo
    print_green "Summary of action:
  You are proposing to update canister $CANISTER_ID ($CAPITALIZED_CANISTER_NAME) to commit $VERSION.
  The WASM hash is $WASM_SHA.
    "

    check_or_set_dfx_hsm_pin

    cmd=($IC_ADMIN --use-hsm --slot=0
        --key-id=01 --pin="$DFX_HSM_PIN"
        --nns-url "https://nns.ic0.app"
        propose-to-change-nns-canister --mode=upgrade
        --canister-id=$CANISTER_ID
        --wasm-module-path=$WASM
        --wasm-module-sha256=$WASM_SHA
        --summary-file=$PROPOSAL_FILE
        --proposer=$NEURON_ID)

    echo "Going to run command: "
    echo ${cmd[@]} | sed 's/pin=[0-9]*/pin=\*\*\*\*\*\*/' | fold -w 100 -s | sed -e "s|^|     |g"

    echo "Type 'yes' to confirm, anything else, or Ctrl+C to cancel"
    read CONFIRM

    if [ "$CONFIRM" != "yes" ]; then
        echo "Aborting proposal execution..."
        exit 1
    fi

    "${cmd[@]}"
}

# We download a verison of IC_ADMIN compatible with the previous release
if ! is_variable_set IC_ADMIN; then
    if [ ! -f "$MY_DOWNLOAD_DIR/ic-admin" ]; then
        PREVIOUS_VERSION=$(extract_previous_version "$PROPOSAL_FILE")
        echo $PREVIOUS_VERSION
        install_binary ic-admin "$PREVIOUS_VERSION" "$MY_DOWNLOAD_DIR"
    fi
    IC_ADMIN=$MY_DOWNLOAD_DIR/ic-admin
fi

submit_proposal_mainnet $PROPOSAL_FILE $NEURON_ID
