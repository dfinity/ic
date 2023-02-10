#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$SCRIPT_DIR/functions.sh"

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

value_from_proposal_text() {
    local FILE=$1
    local FIELD=$2
    cat $FILE | grep "### $FIELD" | sed "s/.*$FIELD[[:space:]]*//"
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

submit_nns_publish_sns_wasm_proposal_mainnet() {
    ensure_variable_set IC_ADMIN

    PROPOSAL_FILE=$1
    NEURON_ID=$2

    VERSION=$(value_from_proposal_text "$PROPOSAL_FILE" "Git Hash:")
    PROPOSAL_SHA=$(value_from_proposal_text "$PROPOSAL_FILE" "New Wasm Hash:")
    TITLE_CANISTER_TYPE=$(cat $PROPOSAL_FILE | grep "## Proposal to Publish the SNS" | cut -d' ' -f7)
    NORMALIZED_TITLE_CANISTER_TYPE="$(tr '[:upper:]' '[:lower:]' <<<${TITLE_CANISTER_TYPE:0:1})${TITLE_CANISTER_TYPE:1}"
    CANISTER_TYPE="$(value_from_proposal_text "$PROPOSAL_FILE" "Canister Type:")${CAPITALIZED_CANISTER_TYPE:1}"

    if [ "$CANISTER_TYPE" != "$NORMALIZED_TITLE_CANISTER_TYPE" ]; then
        echo "Request malformed, title canister type does not match 'Canister Type' in proposal header."
        return 1
    fi

    echo >&2 $VERSION

    WASM_GZ=$(get_sns_canister_wasm_gz_for_type "$CANISTER_TYPE" "$VERSION")
    WASM_SHA=$(sha_256 $WASM_GZ)

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
  You are proposing to publish SNS $TITLE_CANISTER_TYPE canister WASM built from commit $VERSION to the SNS
  blessed upgrade path.
  The WASM hash is $WASM_SHA.
    "

    check_or_set_dfx_hsm_pin

    cmd=($IC_ADMIN --use-hsm --slot=0
        --key-id=01 --pin="$DFX_HSM_PIN"
        --nns-url "https://nns.ic0.app"
        propose-to-add-wasm-to-sns-wasm
        --canister-type=$CANISTER_TYPE
        --wasm-module-path=$WASM_GZ
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

        if [ $(uname -o) != "Darwin" ]; then
            install_binary ic-admin "$PREVIOUS_VERSION" "$MY_DOWNLOAD_DIR"
        else
            echo "IC_ADMIN must be set for Mac, cannot download."
            return 1
        fi
    fi
    IC_ADMIN=$MY_DOWNLOAD_DIR/ic-admin
fi

submit_nns_publish_sns_wasm_proposal_mainnet $PROPOSAL_FILE $NEURON_ID
