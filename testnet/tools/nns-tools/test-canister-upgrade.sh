#!/bin/bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 <CANISTER_NAME> <VERSION> (<CANDID_ARGS> <NNS_URL> <NEURON_ID>)
  CANISTER_NAME: Human readable canister name (from rs/nns/canister_ids.json)
  VERSION: Version to test (generally git hash, could be build id.  Green checkmarks on gitlab commit list have assets)
  CANDID_ARGS: Candid args to encode to include in the request.  Use empty string
   to skip if manually passing NNS_URL and NEURON_ID
  NNS_URL: The url to the subnet running the NNS in your testnet.
  NEURON_ID: The neuron used to submit proposals (should have following to immediately pass)

  NOTE: Both NNS_URL and NEURON_ID can be passed in or set as environment variables.
    Using \"source \$YOUR_WORKING_DIRECTORY/output_vars_nns_state_deployment.sh\" will give you the needed
    variables in your shell.

  NOTE: If testing cycles-minting canister upgrade, you may have to set SKIP_STOPPING=yes in your environment before
    running this script, if your upgrade arguments reference canisters not running on this testnet.

  This script will upgrade a canister on a given testnet with a given neuron id.  If that neuron does not have sufficient
  voting power to pass the proposal, the proposal will still have to be voted in.
  "
    exit 1
}

if [ $# -lt 2 ]; then
    help
fi

CANISTER_NAME=$1
VERSION=$2
CANDID_ARGS=${3:-$(empty_candid_upgrade_args "$CANISTER_NAME")}
NNS_URL=${4:-$NNS_URL}
NEURON_ID=${5:-$NEURON_ID}

ensure_variable_set NNS_URL || help
ensure_variable_set NEURON_ID || help

# Allow overriding PEM file, but default to shared identity
export PEM=${PEM:-$NNS_TOOLS_DIR/test_user.pem}

ENCODED_ARGS_FILE=""
if [ ! -z "$CANDID_ARGS" ]; then
    ENCODED_ARGS_FILE=$(encode_candid_args_in_file "$CANDID_ARGS")
fi

if [ "$CANISTER_NAME" == "cycles-minting" ]; then
    ensure_variable_set XRC_MOCK_CANISTER || (
        print_red "XRC_MOCK_CANISTER must be set as env variable for CMC upgrade"
        help
    )

    # If CMC does not have a current version in metadata, we need to supply it.
    # TODO - remove the ENV variable after CMC is updated
    CURRENT_VERSION=${CURRENT_VERSION:-$(nns_canister_git_version "$NNS_URL" "$CANISTER_NAME")}

    # Get ungzipped version to make it easy to detect upgrade status
    CURRENT_VERSION_UNZIPPED=$(get_nns_canister_wasm_gz_for_type "$CANISTER_NAME" "$CURRENT_VERSION")

    SKIP_STOPPING=yes propose_upgrade_nns_canister_wasm_file_pem "$NNS_URL" \
        "$NEURON_ID" "$PEM" "$CANISTER_NAME" \
        "$CURRENT_VERSION_UNZIPPED" "$(encode_candid_args_in_file \
            "(record {
                exchange_rate_canister = opt variant { Set = principal \"$XRC_MOCK_CANISTER\" } })")"

    if ! wait_for_nns_canister_has_file_contents "$NNS_URL" "$CANISTER_NAME" "$CURRENT_VERSION_UNZIPPED"; then
        print_red "Could not upgrade cycles-minting canister to its own version with different arguments"
        exit 1
    fi
fi

propose_upgrade_canister_to_version_pem "$NNS_URL" "$NEURON_ID" "$PEM" "$CANISTER_NAME" "$VERSION" "$ENCODED_ARGS_FILE"

if ! wait_for_nns_canister_has_version "$NNS_URL" "$CANISTER_NAME" "$VERSION"; then
    print_red "Aborting test"
    exit 1
fi

echo "Testing subsequent upgrade to ensure upgrade path continues to work"

# Download current version, and modify it,
WASM_GZ_FILE=$(get_nns_canister_wasm_gz_for_type "$CANISTER_NAME" "$VERSION")
ORIGINAL_HASH=$(sha_256 $WASM_GZ_FILE)

UNZIPPED=$(ungzip $WASM_GZ_FILE)

NEW_HASH=$(sha_256 "$UNZIPPED")

echo "Checking that hashes are in fact different..."
if [ "$NEW_HASH" == "$ORIGINAL_HASH" ]; then
    print_red "Hashes were the same, aborting rest of test..."
    exit 1
fi

# We upgrade to same version but with a different hash so that we can verify that second upgrade worked.
propose_upgrade_nns_canister_wasm_file_pem "$NNS_URL" "$NEURON_ID" "$PEM" "$CANISTER_NAME" "$UNZIPPED" "$ENCODED_ARGS_FILE"

if wait_for_nns_canister_has_file_contents "$NNS_URL" "$CANISTER_NAME" "$UNZIPPED"; then
    echo "Second upgrade successful..."
    print_green "Canister Upgrade test was successful!"
    exit 0
else
    print_red "Canister Upgrade test FAILED."
    exit 1
fi
