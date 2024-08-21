#!/bin/bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 <PROPOSAL_FILE> <NEURON_ID>
    PROPOSAL_FILE: File with proposal created by
     ./prepare-mainnet-upgrade-proposal-text.sh (or formatted in that way)
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

submit_nns_upgrade_proposal_mainnet() {
    ensure_variable_set IC_ADMIN

    PROPOSAL_FILE=$1
    NEURON_ID=$2

    PROPOSAL_TITLE=$(grep '.' "$PROPOSAL_FILE" | head -n 1 | sed 's/# //')

    VERSION=$(grep '__Source Code__: ' $PROPOSAL_FILE | sed -E 's~.*\[(.{40})\].*~\1~')
    HUMANIZED_CANISTER_NAME=$(echo $PROPOSAL_TITLE | sed -E 's~Upgrade the (.+) Canister to .+~\1~')
    CANISTER_NAME=$(
        echo "$HUMANIZED_CANISTER_NAME" \
            | tr '[:upper:]' '[:lower:]' \
            | sed 's/ /-/g' # Replace spaces with dash.
    )
    CANISTER_ID=$(nns_canister_id "$CANISTER_NAME")

    CANDID_UPGRADE_ARGS=$(extract_candid_upgrade_args "$PROPOSAL_FILE")

    # Functions that exit if error
    validate_no_todos "$PROPOSAL_FILE"

    WASM_GZ=$(get_nns_canister_wasm_gz_for_type "$CANISTER_NAME" "$VERSION")
    WASM_SHA=$(sha_256 $WASM_GZ)

    CANDID_ARGS_FILE=""
    if [ ! -z "$CANDID_UPGRADE_ARGS" ]; then
        CANDID_ARGS_FILE=$(encode_candid_args_in_file "$CANDID_UPGRADE_ARGS")
    fi

    echo_line
    cat "$PROPOSAL_FILE"
    echo_line
    echo

    echo "Upgrade Synopsis:"
    echo "    Target Canister: $HUMANIZED_CANISTER_NAME (NNS)"
    echo "    Build Commit: $VERSION"

    if [ ! -z "$CANDID_ARGS_FILE" ]; then
        echo "    Upgrade Arguments:"
        echo "$CANDID_UPGRADE_ARGS"
        echo
        echo_line
    fi

    echo
    check_or_set_dfx_hsm_pin
    echo

    cmd=(
        $IC_ADMIN
        --nns-url="https://icp-api.io"

        # Auth
        --use-hsm
        --slot=0
        --key-id=01
        --pin="$DFX_HSM_PIN"

        propose-to-change-nns-canister

        # Description
        --proposal-title="$PROPOSAL_TITLE"
        --summary-file="$PROPOSAL_FILE"

        # Action
        --canister-id="$CANISTER_ID"
        --mode=upgrade
        --wasm-module-path="$WASM_GZ"

        # Misc
        --wasm-module-sha256="$WASM_SHA"
        --proposer="$NEURON_ID"
    )

    if [ ! -z "$CANDID_ARGS_FILE" ]; then
        cmd+=(--arg=$CANDID_ARGS_FILE)
    fi

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

# Select version of ic-admin.
if ! is_variable_set IC_ADMIN; then
    if [ ! -f "$MY_DOWNLOAD_DIR/ic-admin" ]; then
        PREVIOUS_VERSION=$(extract_previous_version "$PROPOSAL_FILE")
        install_binary ic-admin "$PREVIOUS_VERSION" "$MY_DOWNLOAD_DIR"
    fi
    IC_ADMIN=$MY_DOWNLOAD_DIR/ic-admin
fi

submit_nns_upgrade_proposal_mainnet $PROPOSAL_FILE $NEURON_ID
