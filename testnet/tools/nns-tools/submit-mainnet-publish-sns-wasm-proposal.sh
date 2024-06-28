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

submit_nns_publish_sns_wasm_proposal_mainnet() {
    ensure_variable_set IC_ADMIN

    PROPOSAL_FILE=$1
    NEURON_ID=$2

    VERSION=$(proposal_header_field_value "$PROPOSAL_FILE" "Git Hash:")
    PROPOSAL_SHA=$(proposal_header_field_value "$PROPOSAL_FILE" "New Wasm Hash:")
    TITLE_CANISTER_TYPE=$(cat $PROPOSAL_FILE | grep "## Proposal to Publish the SNS" | cut -d' ' -f7)
    NORMALIZED_TITLE_CANISTER_TYPE="$(tr '[:upper:]' '[:lower:]' <<<${TITLE_CANISTER_TYPE:0:1})${TITLE_CANISTER_TYPE:1}"
    CANISTER_TYPE="$(proposal_header_field_value "$PROPOSAL_FILE" "Canister Type:")"

    if [ "$CANISTER_TYPE" != "$NORMALIZED_TITLE_CANISTER_TYPE" ]; then
        echo "Request malformed, title canister type does not match 'Canister Type' in proposal header."
        return 1
    fi

    echo >&2 $VERSION

    # Functions that exit if error
    validate_sns_version_wasm_sha "$CANISTER_TYPE" "$VERSION" "$PROPOSAL_SHA"
    validate_no_todos "$PROPOSAL_FILE"

    WASM_GZ=$(download_sns_canister_wasm_gz_for_type "$CANISTER_TYPE" "$VERSION")
    WASM_SHA=$(sha_256 $WASM_GZ)

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
        --nns-url "https://icp-api.io"
        propose-to-add-wasm-to-sns-wasm
        --canister-type=$CANISTER_TYPE
        --wasm-module-path=$WASM_GZ
        --wasm-module-sha256=$WASM_SHA
        --summary-file=$PROPOSAL_FILE
        --proposer=$NEURON_ID)

    confirm_submit_proposal_command "${cmd[@]}"

    "${cmd[@]}"

}

# We download a version of IC_ADMIN compatible with the previous release
if ! is_variable_set IC_ADMIN; then
    if [ ! -f "$MY_DOWNLOAD_DIR/ic-admin" ]; then
        PREVIOUS_VERSION=$(extract_previous_version "$PROPOSAL_FILE")
        install_binary ic-admin "$PREVIOUS_VERSION" "$MY_DOWNLOAD_DIR"
    fi
    IC_ADMIN=$MY_DOWNLOAD_DIR/ic-admin
fi

submit_nns_publish_sns_wasm_proposal_mainnet $PROPOSAL_FILE $NEURON_ID
