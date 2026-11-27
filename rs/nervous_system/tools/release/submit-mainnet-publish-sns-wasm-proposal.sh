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
   SKIP_CONFIRMATION: If set to true, submit without asking for confirmation.
    submit-governance-upgrade-proposals.sh sets this, because it asks for
    confirmation of all its proposals up front.
   DFX_HSM_PIN: If set, used instead of prompting for your HSM PIN.

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
SKIP_CONFIRMATION="${SKIP_CONFIRMATION:-false}"

submit_nns_publish_sns_wasm_proposal_mainnet() {
    ensure_variable_set IC_ADMIN

    PROPOSAL_FILE=$1
    NEURON_ID=$2

    VERSION=$(grep '__Source code__: ' $PROPOSAL_FILE | sed -E 's~.*\[(.{40})\].*~\1~')
    PROPOSAL_TITLE=$(grep '.' "$PROPOSAL_FILE" | head -n 1 | sed 's/# //')
    HUMANIZED_CANISTER_TYPE=$(echo "$PROPOSAL_TITLE" | sed -E 's/Publish SNS (.+) WASM Built at Commit .+/\1/')
    CANISTER_TYPE=$(echo "$HUMANIZED_CANISTER_TYPE" | tr '[:upper:]' '[:lower:]' | sed 's/ /-/')

    # Functions that exit if error
    validate_no_todos "$PROPOSAL_FILE"

    WASM_GZ=$(download_sns_canister_wasm_gz_for_type "$CANISTER_TYPE" "$VERSION")
    WASM_SHA=$(sha_256 $WASM_GZ)

    # Show what we are about to submit, in full gory detail.
    echo_line
    cat "$PROPOSAL_FILE"
    echo_line
    echo

    # Briefly, explain what is about to happen to the user.
    echo "Publish SNS WASM Synopsis:"
    echo "    Target canister: $HUMANIZED_CANISTER_TYPE (SNS)"
    echo "    Build Commit: $VERSION"
    echo
    echo_line
    echo

    # Prompt the user to confirm the above is what they want.
    # Unless they waive confirmation (and supplied HSM pin).
    if [ -z "${DFX_HSM_PIN:-}" ]; then
        confirm_by_entering_dfx_hsm_pin
    elif [ "$SKIP_CONFIRMATION" != true ]; then
        confirm
    fi

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

    submit_proposal_using_ic_admin "${cmd[@]}"
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
