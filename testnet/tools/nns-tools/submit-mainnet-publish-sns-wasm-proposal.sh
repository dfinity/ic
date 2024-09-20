#!/bin/bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 <PROPOSAL_FILE> <NEURON_ID>
    PROPOSAL_FILE: File with proposal created by
     ./prepare-publish-sns-wasm-proposal-text.sh (or formatted in that way)
    NEURON_ID: Your mainnet neuron ID, associated with your HSM

  Environment Variables:
   DRY_RUN: If set to true, no proposal will be created, but other than that,
    this script will do as much as it would otherwise.

  This script will create a proposal on mainnet from a given proposal text. It
  outputs the values for confirmation, and ensures that the target version
  matches the target hash.
  "
    exit 1
}

if [ $# -ne 2 ]; then
    help
fi

PROPOSAL_FILE=$1
NEURON_ID=$2

DRY_RUN="${DRY_RUN:-false}"

submit_nns_publish_sns_wasm_proposal_mainnet() {
    ensure_variable_set IC_ADMIN

    PROPOSAL_FILE=$1
    NEURON_ID=$2

    VERSION=$(grep '__Source Code__: ' $PROPOSAL_FILE | sed -E 's~.*\[(.{40})\].*~\1~')
    PROPOSAL_TITLE=$(grep '.' "$PROPOSAL_FILE" | head -n 1 | sed 's/# //')
    HUMANIZED_CANISTER_TYPE=$(echo "$PROPOSAL_TITLE" | sed -E 's/Publish SNS (.+) WASM Built at Commit .+/\1/')
    CANISTER_TYPE=$(echo "$HUMANIZED_CANISTER_TYPE" | tr '[:upper:]' '[:lower:]' | sed 's/ /-/')

    # Functions that exit if error
    validate_no_todos "$PROPOSAL_FILE"

    WASM_GZ=$(download_sns_canister_wasm_gz_for_type "$CANISTER_TYPE" "$VERSION")
    WASM_SHA=$(sha_256 $WASM_GZ)

    echo_line
    cat "$PROPOSAL_FILE"
    echo_line
    echo

    echo "Publish SNS WASM Synopsis:"
    echo "    Target Canister: $HUMANIZED_CANISTER_TYPE"
    echo "    Build Commit: $VERSION"

    echo
    check_or_set_dfx_hsm_pin
    echo

    cmd=(
        $IC_ADMIN
        --nns-url "https://icp-api.io"

        # Auth
        --use-hsm
        --slot=0
        --key-id=01
        --pin="$DFX_HSM_PIN"

        propose-to-add-wasm-to-sns-wasm

        # Description
        --proposal-title="$PROPOSAL_TITLE"
        --summary-file=$PROPOSAL_FILE

        # Action
        --canister-type=$CANISTER_TYPE
        --wasm-module-path=$WASM_GZ

        # Misc
        --wasm-module-sha256=$WASM_SHA
        --proposer=$NEURON_ID
    )

    if [ "$DRY_RUN" = true ]; then
        cmd+=(--dry-run)
    fi

    confirm_submit_proposal_command "${cmd[@]}"
    echo

    echo "Sending the proposal..."
    echo

    echo_line
    if ! RESPONSE=$("${cmd[@]}"); then
        echo "$RESPONSE"
        echo_line
        echo
        echo "😬 It very much seems that the proposal was NOT submitted, because"
        echo "ic-admin failed. See its output above. It could be you entered"
        echo "the wrong PIN for your HSM. In that case, trying again should work."
        exit 1
    fi
    echo "$RESPONSE"
    echo_line
    PROPOSAL_ID=$(echo "${RESPONSE}" | grep -o 'proposal [0-9]*' | awk '{print $2}' | tr -d '[:space:]')

    # Report conclusion.
    echo
    if [ "$DRY_RUN" = true ]; then
        print_yellow "This was just a dry run. Still, everything went ok."
    else
        echo "🎉 Success!"
        echo "https://dashboard.internetcomputer.org/proposal/${PROPOSAL_ID}"
    fi
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
